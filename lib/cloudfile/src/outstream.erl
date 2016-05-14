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
-module(outstream).
-author("epappas").

-include("cloudfile.hrl").

%% API
-export([
  stream/4
]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

stream(AuthKeyType, AuthKey, FileKey, Req) ->
    doStreamFileOutbound(AuthKeyType, AuthKey, FileKey, Req).

%%%===================================================================
%%% Internal functions
%%%===================================================================

doStreamFileOutbound(AuthKeyType, AuthKey, FileKey, Req) ->

    case ?FILE_GET(FileKey) of
        {ok, FileKVList} ->

            {[{Filename, _FileInfo}]} = proplists:get_value(<<"_attachments">>, FileKVList),

            {ok, Out_StreamPID} = gen_stream:start(outcfstore_stream, outcfstore_stream, [
                {"auth_type", AuthKeyType},
                {"auth_key", AuthKey},
                {"file_key", FileKey},
                {"filename", Filename}
            ]),

            StreamFun = fun(SendChunk) ->
                outStream_loop_file(SendChunk, Out_StreamPID, Req)
            end,

            Req2 = ?HTTP_CHUNKED_RESP(StreamFun, Req),

            ReqLast = ?HTTP_ECHO(200, <<"application/octet-stream">>, undefined, Req2);
        {error, not_found} ->
            ReqLast = ?HTTP_END_FAILURE(404, "Not Found", Req)
    end,

    {ok, ReqLast}.

outStream_loop_file(SendChunk, Out_StreamPID, Req) ->

    case gen_stream:take(Out_StreamPID) of
        {ok, {more, Chunk}} ->
            SendChunk(Chunk),
            outStream_loop_file(SendChunk, Out_StreamPID, Req);
        {ok, {ok, ResultDoc}} ->
            {ok, ResultDoc};
        ELSE ->
            ?HTTP_END_FAILURE(500, "Transport issue", Req)
    end.
