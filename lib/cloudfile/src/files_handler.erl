%%% -*- erlang -*-
%%%-------------------------------------------------------------------
%%% @author Evangelos Pappas <epappas@evalonlabs.com>
%%% @copyright (C) 2014, evalonlabs
%%% Copyright 2015, evalonlabs
%%%
%%% Licensed under the Apache License, Version 2.0 (the 'License');
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an 'AS IS' BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(files_handler).
-author("epappas").

-include("cloudfile.hrl").

-export([init/2]).
-export([handle/2]).
-export([terminate/3]).

-record(state, {
    method, isAuthorized = false,
    is_conflict = false, etag,
    key_type, key, salt, scope
}).

init(Req, _Opts) ->
    handle(Req, #state{}).

handle(Req, State) ->
    Method = cowboy_req:method(Req),

    % ScopeList =
    %     case Method of
    %       <<"GET">> -> [<<"download_files">>];
    %       <<"PUT">> -> [<<"upload_files">>];
    %       _ -> []
    %     end,

    {ok, Req2} = process(Req, State#state{
        method = Method,
        isAuthorized = true,
        key_type = aukey,
        key = <<"">>,
        salt = <<"">>,
        scope = <<"">>
    }),

    {ok, Req2, []}.

process(Req, #state{method = <<"GET">>, isAuthorized = true, key_type = KeyType, key = Key} = _State) ->
    QsVals = cowboy_req:parse_qs(Req),
    FileKeyBin = cowboy_req:binding(key, Req),
    FileSwitch = proplists:get_value(<<"file">>, QsVals, false),

    %% check if File name is defined
    case FileKeyBin of
        undefined -> ?HTTP_END_FAILURE(400, "No Valid Arguments", Req);
        FileKeyBin ->
            FileKey = binary:bin_to_list(FileKeyBin),

            %% Fork responce whether the attachment is requested or not
            case FileSwitch of
                false -> %% When only File info is requested
                    case ?FILE_DETAILS(FileKey) of
                        {ok, FileKVList} ->
                            ?HTTP_END_SUCCESS({FileKVList}, Req);
                        _ ->
                            ?HTTP_END_FAILURE(404, "Not Found", Req)
                    end;
                true -> %% When the actual file content is requested
                    outstream:stream(KeyType, Key, FileKey, Req)
            end
    end;

process(Req, #state{method = <<"PUT">>, isAuthorized = true, key_type = KeyType, key = Key} = _State) ->
    case cowboy_req:parse_header(<<"content-type">>, Req) of
        {<<"multipart">>, <<"form-data">>, _} ->
            case multipartstream_server:stream(KeyType, Key, Req) of
                {ok, Req2, FileList} ->
                    ?HTTP_END_SUCCESS({[
                        {fileList, {FileList}}
                    ]}, Req2);
                _ ->
                    ?HTTP_END_FAILURE(415, <<"Unsupported Media Type">>, Req)
            end;
        _ ->
            case instream:stream(KeyType, Key, Req) of
                {ok, Req2, FileList} ->
                    ?HTTP_END_SUCCESS({[
                        {fileList, {FileList}}
                    ]}, Req2);
                _ ->
                    ?HTTP_END_FAILURE(415, <<"Unsupported Media Type">>, Req)
            end
    end;

process(Req, _) -> ?HTTP_END_FAILURE(405, "Method not allowed.", Req).

terminate(_Reason, _Req, _State) -> ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
