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

-module(encrypt_stream).
-author("epappas").

-behaviour(gen_stream).

-include("cfile.hrl").

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
    aes_key, aes_iv, file_key,
    crypto_state, done = false
}).

%%%===================================================================
%%% API
%%%===================================================================

init(Args) ->
    FileKey = proplists:get_value("file_key", Args),

    AESKey = crypto:strong_rand_bytes(32), %% 256 bts long
    AESIV = crypto:strong_rand_bytes(16),

    %% Initiate crypto stream
    CryptoState = crypto:stream_init(aes_ctr, AESKey, AESIV),

    {ok, #state{
        aes_key = AESKey,
        aes_iv = AESIV,
        file_key = FileKey,
        crypto_state = CryptoState
    }}.

on_data(_Resource, Stream, #state{done = false} = State) ->
    {ok, Stream, State};

on_data(_Resource, Stream, #state{done = true} = State) ->
    {ignore, Stream, State}.

on_offer(Message, Stream, #state{done = true} = State) ->
    {Message, Stream, State};

on_offer(undefined, Stream, #state{} = State) ->
    {undefined, Stream, State};

on_offer(#cfmsg{body = Body, done = false} = Message, Stream, #state{
    done = false, crypto_state = CryptoState,
    file_key = FileKey, aes_key = AESKey,
    aes_iv = AESIV
} = State) ->
    {NewCryptoState, CipherBody} = crypto:stream_encrypt(CryptoState, Body),

    NewMessage = Message#cfmsg{
        body = CipherBody,
        file_key = FileKey,
        aes_key = AESKey,
        aes_iv = AESIV
    },

    {NewMessage, Stream, State#state{crypto_state = NewCryptoState}};

on_offer(#cfmsg{body = Body, done = true} = Message, Stream, #state{
    done = false, crypto_state = CryptoState,
    file_key = FileKey, aes_key = AESKey,
    aes_iv = AESIV
} = State) ->

    {NewCryptoState, CipherBody} = crypto:stream_encrypt(CryptoState, Body),

    NewMessage = Message#cfmsg{
        file_key = FileKey,
        body = CipherBody,
        done = true,
        aes_key = AESKey,
        aes_iv = AESIV
    },

    {NewMessage, Stream, State#state{
        done = true,
        crypto_state = NewCryptoState
    }}.

on_state(#state{} = _State, _Stream, StateData) ->
    {ok, StateData}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
