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
-module(instream).
-author("epappas").

-include("cloudfile.hrl").

%% API
-export([
  stream/3
]).

%%%===================================================================
%%% API
%%%===================================================================

stream(AuthKeyType, AuthKey, Req) -> body_stream(AuthKeyType, AuthKey, Req).

%%%===================================================================
%%% Internal functions
%%%===================================================================

body_stream(AuthKeyType, AuthKey, Req) -> body_stream(AuthKeyType, AuthKey, Req, []).

body_stream(_AuthKeyType, AuthKey, Req, FileList) ->

    FileKey = crypto_util:uuid(),
    Filename = list_to_binary(crypto_util:uuid()),
    % CType = cowboy_req:parse_header(<<"content-type">>, Req, undefined),
    CType = undefined,
    CTransferEncoding = cowboy_req:parse_header(<<"transfer-encoding">>, Req, undefined),
    %% CLength = cowboy_req:parse_header(<<"content-length">>, Req, 0),

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
    {ok, Req2} = inStream_loop_file(Req, LeftStream),

    {ok, ResultDoc} = result_loop(Encrypt_StreamPID),

    %% Generate a responce list
    {ok, Req2, [{Filename, ResultDoc}]}.

%% Handy loop
inStream_loop_file(Req, LeftStream) ->
    Opts = [{continue, true},
        {length, 8000000},
        {read_length, 1000000},
        {read_timeout, 15000}
    ],

    case cowboy_req:body(Req, Opts) of
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
