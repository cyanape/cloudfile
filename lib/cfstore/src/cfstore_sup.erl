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

-module(cfstore_sup).
-author("epappas").

-behaviour(supervisor).

%% API.
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, Application} = application:get_application(),

    StoreChild =
        case application:get_env(Application, store_engine) of
          undefined -> init_couch_engine(Application);
          couch -> init_couch_engine(Application);
          _ -> throw(unkown_cfstore_engine)
        end,

    pg2:create(cfstore_listeners),
    {ok, {{one_for_one, 10, 10}, [
        StoreChild,
        ?CHILD(ecache, worker)
    ]}}.

%% ===================================================================
%% Internal callbacks
%% ===================================================================

init_couch_engine(Application) ->
    CouchUrl =
      case application:get_env(Application, couch_port) of
        undefined -> application:get_env(Application, couch_url, "http://localhost:5984");
        COUCH_PORT ->
          re:replace(COUCH_PORT, "tcp", "http", [global, {return, list}])
      end,
    CouchOpts = application:get_env(Application, couch_opts, []),

    {couch,
        {couch, start_link, [CouchUrl, CouchOpts]},
        permanent, 1000, worker,
        [couch]}.
