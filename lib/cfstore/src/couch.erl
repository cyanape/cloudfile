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

-module(couch).
-author("epappas").

-behaviour(cfstore).

%% gen_server callbacks
-export([
    init/1,
    handle/2
]).

-record(state, {server, dbList = []}).

%%%===================================================================
%%% API callbacks
%%%===================================================================

-spec(init(Args :: term()) ->
    {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
    {stop, Reason :: term()} | ignore).

init([]) -> init(["http://localhost:5984", []]);

init([Url, Options]) ->
    Server = couchbeam:server_connection(Url, Options),
    {ok, _Version} = couchbeam:server_info(Server),
    State = #state{server = Server, dbList = []},
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Create a DB (or just Open it)
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle(Request :: term(), State :: #state{}) ->
        {{ok, DB :: term()}, NewState :: #state{}}).
handle({create_db, DBName}, State) ->
    case db(State, DBName, []) of
        {ok, DB, State2} -> {{ok, DB}, State2};
        Error -> {{error, Error}, State}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Save a Doc to a DB
%%
%% @end
%%--------------------------------------------------------------------
handle({save_doc, DBName, Doc}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam:save_doc(DB, Doc) of
        {ok, Doc1} -> {{ok, Doc1}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% GET a Doc by ref from a DB
%%
%% @end
%%--------------------------------------------------------------------
handle({get_doc, DBName, Ref, Options}, State) ->
    {ok, DB, State2} = db(State, DBName, Options),

    case couchbeam:open_doc(DB, Ref) of
        {ok, Doc1} -> {{ok, Doc1}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% LIST all Docs from a DB
%%
%% @end
%%--------------------------------------------------------------------
handle({all_docs, DBName, Options}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam_view:fetch(DB, 'all_docs', Options) of
        {ok, AllDocs} -> {{ok, AllDocs}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% LIST Docs from a view of a DB
%%
%% @end
%%--------------------------------------------------------------------
handle({fetch_docs, DBName, {DesignName, ViewName}, Options}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam_view:fetch(DB, {DesignName, ViewName}, Options) of
        {ok, AllDocs} -> {{ok, AllDocs}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Set an Attachment to a Doc
%%
%% @end
%%--------------------------------------------------------------------
handle({attach_doc, DBName, Ref, {Name, Attachment}, Options}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam:put_attachment(DB, Ref, Name, Attachment, Options) of
        {ok, Result} -> {{ok, Result}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% stream an Attachment
%%
%% @end
%%--------------------------------------------------------------------
handle({stream_attach, Ref, Msg}, State) ->
    case couchbeam:send_attachment(Ref, Msg) of
        {error, Error} -> {{error, Error}, State};
        Result -> {Result, State}
    end;

handle({stream_attachment, Ref}, State) ->
    case couchbeam:stream_attachment(Ref) of
        {error, Error} -> {{error, Error}, State};
        done -> {{ok, done}, State};
        Result -> {Result, State}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% fetch an Attachment from a Doc
%%
%% @end
%%--------------------------------------------------------------------
handle({fetch_attachment, DBName, Ref, Name}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam:fetch_attachment(DB, Ref, Name) of
        {ok, Result} -> {{ok, Result}, State2};
        Error -> {{error, Error}, State2}
    end;
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Stream an Attachment from a Doc
%%
%% @end
%%--------------------------------------------------------------------
handle({fetch_attachment_stream, DBName, Ref, Name}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam:fetch_attachment(DB, Ref, Name, [stream]) of
        {ok, Ref1} -> {{ok, Ref1}, State2};
        Error -> {{error, Error}, State2}
    end;

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handle Streamed rows
%%
%% @end
%%--------------------------------------------------------------------
handle({stream_docs, DBName, {DesignName, ViewName}, {Pid, ViewFun}}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam_view:stream(DB, {DesignName, ViewName}, Pid) of
        {ok, StartRef, ViewPid} ->
            ViewFun(StartRef, ViewFun, ViewPid),
            {ok, State2};
        _Error -> {ok, State2} %% TODO Handle this somehow
    end;

handle({drop_attachment, DBName, Ref, Name}, State) ->
    {ok, DB, State2} = db(State, DBName, []),

    case couchbeam:open_doc(DB, Ref) of
        {ok, Doc1} ->
            ok = couchbeam:delete_attachment(DB, Doc1, Name),
            {ok, State2};
        _Error -> {ok, State2} %% TODO Handle this somehow
    end;

handle(_Request, State) -> {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

db(State, DBName, Options) ->
    CurrentList = case is_list(State#state.dbList) of
        false -> lists:flatten([State#state.dbList]);
        true -> State#state.dbList
    end,
    case lists:keyfind(DBName, 1, CurrentList) of
        {DBName, DB} -> {ok, DB, State};
        false ->
            {ok, DB} = couchbeam:open_or_create_db(State#state.server, DBName, Options),
            %% TODO case for {error,econnrefused}
            State2 = State#state{dbList = lists:append(CurrentList, [{DBName, DB}])},
            {ok, DB, State2}
    end.
