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

-module(outcfstore_stream).
-author("epappas").

-behaviour(gen_stream).

-include("cloudfile.hrl").

%% API

%% gen_stream callbacks
-export([
    init/1,
    on_data/3,
    on_offer/3,
    on_state/3
]).

-define(SERVER, ?MODULE).

-record(state, {
    download_ref, result, done = false, auth_key,
    file_name, file_key, ctype, ctransfer_encoding
}).

%%%===================================================================
%%% API
%%%===================================================================

init(Args) ->
    % AuthKeyType = proplists:get_value("auth_type", Args),
    AuthKey = proplists:get_value("auth_key", Args),
    FileKey = proplists:get_value("file_key", Args),
    Filename = proplists:get_value("filename", Args),
    FileKeyBin = list_to_binary(FileKey),

    {ok, StreamRef} = ?FILE_OUTSTREAM(FileKeyBin, Filename),

    % {ok, EssentialsJson} = couch:get(?couch_file_secrets, FileKeyBin)
    % AESKey64 = proplists:get_value(<<"aes_key">>, EKVList),
    % AESIV64 = proplists:get_value(<<"aes_iv">>, EKVList),
    % AESKey = base64:decode(AESKey64),
    % AESIV = base64:decode(AESIV64),

    {ok, #state{
        download_ref = StreamRef,
        % ctype = CType,
        % ctransfer_encoding = CTransferEncoding,
        file_key = FileKeyBin,
        file_name = Filename,
        auth_key = AuthKey
    }}.

on_data(_Message, Stream, #state{} = State) ->
    {ignore, Stream, State}.

on_offer(_Message, Stream, #state{done = true} = State) ->
    {undefined, Stream, State};

on_offer(_Message, Stream, #state{
    done = false, download_ref = StreamRef, file_name = Filename
} = State) ->

    case couchbeam:stream_attachment(StreamRef) of
        {ok, Chunk} ->
            {{more, Chunk}, Stream, State#state{done = false}};
        done ->
            Doc = [{file_name, Filename}],
            {{ok, Doc}, Stream, State#state{done = true}};
      {error, Err} ->
            {{error, Err}, Stream, State#state{done = true}}
    end.

on_state(#state{} = _State, _Stream, StateData) ->
    {ok, StateData}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
