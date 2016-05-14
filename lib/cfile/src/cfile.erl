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

-module(cfile).
-author("epappas").

%% Application callbacks
-export([
    start_instream/1,
    get/2,
    amend_stream/2
]).

-include("cfile.hrl").

get(info, {file, FileKey}) ->
    #file_info{
        file_key = FileKey,
        md5 = undefined,
        sha = undefined,
        sha512 = undefined
    }.

start_instream(FileKey) ->
    Common_Stream_Args = [
        {"file_key", FileKey}
    ],

    {ok, HMAC_StreamPID} = gen_stream:start(hmac_stream, hmac_stream, Common_Stream_Args),
    {ok, Deflate_StreamPID} = gen_stream:start(deflate_stream, deflate_stream, Common_Stream_Args),
    {ok, Encrypt_StreamPID} = gen_stream:start(encrypt_stream, encrypt_stream, Common_Stream_Args),

    gen_stream:pipe(HMAC_StreamPID, Deflate_StreamPID),
    gen_stream:pipe(Deflate_StreamPID, Encrypt_StreamPID),

    {ok, HMAC_StreamPID, Encrypt_StreamPID}.

amend_stream(StreamPID, {more, Body}) ->
    gen_stream:put(StreamPID, #cfmsg{body = Body});

amend_stream(StreamPID, {ok, Body}) ->
    gen_stream:put(StreamPID, #cfmsg{body = Body, done = true}).
