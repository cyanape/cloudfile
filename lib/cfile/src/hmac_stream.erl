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

-module(hmac_stream).
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
    file_key, md5_context,
    sha_context, sha512_context,
    done = false
}).

%%%===================================================================
%%% API
%%%===================================================================

init(Args) ->
    FileKey = proplists:get_value("file_key", Args),

    %% Initiate hash contexts
    MD5_Context = crypto:hmac_init(md5, FileKey),
    SHA_Context = crypto:hmac_init(sha, FileKey),
    SHA512_Context = crypto:hmac_init(sha512, FileKey),

    {ok, #state{
        file_key = FileKey,
        md5_context = MD5_Context,
        sha_context = SHA_Context,
        sha512_context = SHA512_Context
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
    done = false, md5_context = MD5_Context,
    sha_context = SHA_Context,
    sha512_context = SHA512_Context,
    file_key = FileKey
} = State) ->
    NewMD5_Context = crypto:hmac_update(MD5_Context, Body),
    NewSHA_Context = crypto:hmac_update(SHA_Context, Body),
    NewSHA512_Context = crypto:hmac_update(SHA512_Context, Body),

    NewMessage = Message#cfmsg{
        file_key = FileKey,
        body = Body,
        done = false,
        md5 = NewMD5_Context,
        sha = NewSHA_Context,
        sha512 = NewSHA512_Context
    },

    {NewMessage, Stream, State#state{
        md5_context = NewMD5_Context,
        sha_context = NewSHA_Context,
        sha512_context = NewSHA512_Context
    }};

on_offer(#cfmsg{body = Body, done = true} = Message, Stream, #state{
    done = false, file_key = FileKey,
    md5_context = MD5_Context,
    sha_context = SHA_Context,
    sha512_context = SHA512_Context
} = State) ->

    NewMD5_Context = crypto:hmac_update(MD5_Context, Body),
    NewSHA_Context = crypto:hmac_update(SHA_Context, Body),
    NewSHA512_Context = crypto:hmac_update(SHA512_Context, Body),

    MD5 = crypto:hmac_final(MD5_Context),
    SHA = crypto:hmac_final(SHA_Context),
    SHA512 = crypto:hmac_final(SHA512_Context),

    NewMessage = Message#cfmsg{
        file_key = FileKey,
        body = Body,
        done = true,
        md5 = MD5,
        sha = SHA,
        sha512 = SHA512
    },

    {NewMessage, Stream, State#state{
        done = true,
        md5_context = NewMD5_Context,
        sha_context = NewSHA_Context,
        sha512_context = NewSHA512_Context
    }}.

on_state(#state{} = _State, _Stream, StateData) ->
    {ok, StateData}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
