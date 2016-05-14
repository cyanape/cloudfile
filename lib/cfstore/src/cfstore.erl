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

-module(cfstore).
-author("epappas").

%% API
-export([
  create_db/1,
  save/2,
  save/3,
  get/2,
  get/3,
  all/1,
  all/2,
  fetch/2,
  fetch/3,
  stream/3,
  attach/4,
  fetch_attachment/3,
  fetch_attachment_stream/3,
  drop_attachment/3,
  stream_attach/2,
  stream_attach_done/1,
  stream_attachment_fetch/1]).

-define(CFSTORE, couch).

%%%===================================================================
%%% API
%%%===================================================================

-spec(create_db(DBName :: term()) -> {ok, DB :: term()}).
create_db(DBName) -> gen_server:call(?CFSTORE, {create_db, DBName}).

-spec(save(DBName :: term(), Doc :: term()) -> {ok, Doc :: term()}).
save(DBName, Doc) -> gen_server:call(?CFSTORE, {save_doc, DBName, Doc}).

save(DBName, Doc, RefRev) ->
  {DocKVList} = Doc,
  gen_server:call(?CFSTORE, {
    save_doc, DBName, {lists:concat([
      RefRev,
      DocKVList
    ])}}).

-spec(get(DBName :: term(), Ref :: term()) -> {ok, Doc :: term()}).
get(DBName, Ref) -> gen_server:call(?CFSTORE, {get_doc, DBName, Ref, []}).

-spec(get(DBName :: term(), Ref :: term(), Rev :: term()) -> {ok, Doc :: term()}).
get(DBName, Ref, Rev) -> gen_server:call(?CFSTORE, {get_doc, DBName, Ref, [{rev, Rev}]}).

-spec(all(DBName :: term()) -> {ok, [Docs :: term()]}).
all(DBName) -> gen_server:call(?CFSTORE, {all_docs, DBName, []}).

-spec(all(DBName :: term(), included) -> {ok, [Docs :: term()]}).
all(DBName, included) -> gen_server:call(?CFSTORE, {all_docs, DBName, [include_docs]}).

-spec(fetch(DBName :: term(), {DesignName :: term(), ViewName :: term()}) -> {ok, [Docs :: term()]}).
fetch(DBName, {DesignName, ViewName}) ->
  gen_server:call(?CFSTORE, {fetch_docs, DBName, {DesignName, ViewName}, []}).

-spec(fetch(DBName :: term(),
    {DesignName :: term(), ViewName :: term()},
    Opts :: term()) -> {ok, [Docs :: term()]}).
fetch(DBName, {DesignName, ViewName}, Opts) ->
  gen_server:call(?CFSTORE, {fetch_docs, DBName, {DesignName, ViewName}, Opts}).

-spec(stream(DBName :: term(),
    {DesignName :: term(), ViewName :: term()},
    {Pid :: term(), ViewFun :: term()}) -> ok).
stream(DBName, {DesignName, ViewName}, {Pid, ViewFun}) ->
  gen_server:cast(?CFSTORE, {stream_docs, DBName, {DesignName, ViewName}, {Pid, ViewFun}}),
  ok.

-spec(attach(DBName :: term(), Ref :: term(),
    {Name :: term(), Attachment :: term()},
    Opts :: term()) -> {ok, Result :: term()}).
attach(DBName, Ref, {Name, Attachment}, Opts) ->
  gen_server:call(?CFSTORE, {attach_doc, DBName, Ref, {Name, Attachment}, Opts}).

stream_attach(Ref, Msg) ->
  gen_server:call(?CFSTORE, {stream_attach, Ref, Msg}).

stream_attach_done(Ref) ->
  gen_server:call(?CFSTORE, {stream_attach, Ref, eof}).

stream_attachment_fetch(Ref) ->
  gen_server:call(?CFSTORE, {stream_attachment, Ref}).

-spec(fetch_attachment(DBName :: term(), Ref :: term(), Name :: term()) ->
  {ok, Attachment :: term()}).
fetch_attachment(DBName, Ref, Name) -> gen_server:call(?CFSTORE, {fetch_attachment, DBName, Ref, Name}).

fetch_attachment_stream(DBName, Ref, Name) -> gen_server:call(?CFSTORE, {fetch_attachment_stream, DBName, Ref, Name}).

-spec(drop_attachment(DBName :: term(), Ref :: term(), Name :: term()) -> ok).
drop_attachment(DBName, Ref, Name) -> gen_server:cast(?CFSTORE, {drop_attachment, DBName, Ref, Name}),
  ok.
