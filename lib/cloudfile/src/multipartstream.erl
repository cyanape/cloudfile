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
-module(multipartstream).
-author("epappas").

-include("cloudfile.hrl").

%% API
-export([
  stream/3
]).

%%%===================================================================
%%% API
%%%===================================================================

stream(AuthKeyType, AuthKey, Req) -> multipart(AuthKeyType, AuthKey, Req, []).

%%%===================================================================
%%% Internal functions
%%%===================================================================

multipart(AuthKeyType, AuthKey, Req, FileList) ->
    case cowboy_req:part(Req) of
        {ok, Headers, Req2} ->
            {ok, Req4, NewFileList} =
                case cow_multipart:form_data(Headers) of
                    {data, _FieldName} -> %% Sneaky, the users wishes to store raw secret information :P
                        {ok, _Body, Req3} = cowboy_req:part_body(Req2),

                        % TODO

                        {ok, Req3, FileList};
                    {file, _FieldName, Filename, CType, CTransferEncoding} -> %% A file/binary detected, lets encrypt everything
                        FileKey = ds_util:uuid(),
                        % FileKeyBin = list_to_binary(FileKey),

                        {ok, LeftStream, RightStream} = cfile:start_instream(FileKey),

                        {ok, Encrypt_StreamPID} = gen_stream:start(incfstore_stream, incfstore_stream, [
                            {"file_key", FileKey},
                            {"auth_key", AuthKey},
                            {"file_name", Filename},
                            {"content_type", CType},
                            {"transfer_encoding", CTransferEncoding}
                        ]),

                        gen_stream:pipe(RightStream, Encrypt_StreamPID),

                        %% commit upload
                        {ok, Req3} = inStream_loop_file(Req2, LeftStream),

                        {ok, ResultDoc} = result_loop(Encrypt_StreamPID),

                        %% Generate a responce list
                        {ok, Req3, [{Filename, ResultDoc}]}
                end,
                %% Next spin, Next multipart of the REQ
                multipart(AuthKeyType, AuthKey, Req4, NewFileList);
        {done, Req2} -> %% All done :D
            {ok, Req2, FileList}
    end.

%% Handy loop
inStream_loop_file(Req, LeftStream) ->
    case cowboy_req:part_body(Req) of
        {ok, Body, Req2} ->
            cfile:amend_stream(LeftStream, {ok, Body}),
            {ok, Req2};
        {more, Body, Req2} ->
            cfile:amend_stream(LeftStream, {more, Body}),
            inStream_loop_file(Req2, LeftStream)
    end.

result_loop(RightStream) ->
    case gen_stream:take(RightStream) of
        {ok, undefined} ->
            timer:sleep(1),
            result_loop(RightStream);
        {ok, ResultDoc} ->
            {ok, ResultDoc};
        Error ->
            {error, Error}
    end.
