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

-module(deflate_stream).
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
    file_key, z_port,
    done = false
}).

%%%===================================================================
%%% API
%%%===================================================================

init(Args) ->
    FileKey = proplists:get_value("file_key", Args),

    %% Initiate zlib port
    Z_Port = zlib:open(),
    ok = zlib:deflateInit(Z_Port, default),

    {ok, #state{
        file_key = FileKey,
        z_port = Z_Port
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
    done = false, file_key = FileKey, z_port = Z_Port
} = State) ->
    CompressedBody = zlib:deflate(Z_Port, Body),

    NewMessage = Message#cfmsg{
        file_key = FileKey,
        body = CompressedBody,
        done = false
    },

    {NewMessage, Stream, State#state{z_port = Z_Port}};

on_offer(#cfmsg{body = Body, done = true} = Message, Stream, #state{
    done = false, file_key = FileKey, z_port = Z_Port
} = State) ->

    CompressedBody = zlib:deflate(Z_Port, Body, finish),
    ok = zlib:deflateEnd(Z_Port),
    zlib:close(Z_Port),

    NewMessage = Message#cfmsg{
        file_key = FileKey,
        body = CompressedBody,
        done = true
    },

    {NewMessage, Stream, State#state{
        done = true, z_port = Z_Port
    }}.

on_state(#state{} = _State, _Stream, StateData) ->
    {ok, StateData}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
