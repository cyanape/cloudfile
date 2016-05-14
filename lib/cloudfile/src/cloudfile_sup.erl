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
-module(cloudfile_sup).
-author("epappas").

-behaviour(supervisor).

%% API.
-export([start_listeners/0, start_listeners/1, start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_listeners() ->
    {ok, Application} = application:get_application(),
    start_listeners(Application).

start_listeners(Application) ->
    Port = application:get_env(Application, http_port, 4421),
    ListenerCount = application:get_env(Application, http_listener_count, 100),

    Dispatch = routing_dispatch(),

    {ok, _} = cowboy:start_http(http, ListenerCount, [{port, Port}], [
        {env, [{dispatch, Dispatch}]},
        {timeout, 12000}
    ]).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, Application} = application:get_application(),

    pg2:create(cloudfile_rest_listeners),
    {ok, {{one_for_one, 10, 10}, [
        {cloudfile,
            {cloudfile_sup, start_listeners, [Application]},
            permanent, 1000, worker,
            [cloudfile_sup]}
    ]}}.

%% ===================================================================
%%% Routing
%% ===================================================================
routing_dispatch() ->
  List = [
    root, index_key,
    files, files_key
  ],
  cowboy_router:compile([
    %% {URIHost, list({URIPath, Handler, Opts})}
    {'_', [route(Name) || Name <- List]}
  ]).

route(root) ->
  {"/", index_handler, []};

route(index_key) ->
  {"/index/:key", index_handler, []};

route(files) ->
  {"/files", files_handler, []};

route(files_key) ->
  {"/files/:key", files_handler, []}.
