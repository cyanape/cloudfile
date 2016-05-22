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
-module(atoken).
-author("epappas").

-export([
    generate/1,
    check/1,
    get_aukey/1
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate(#atoken_generate{aukey = AUKey, scope = Scope, expires = Expires}) ->

    AToken = srp_server:new_salt(),
    Salt = srp_server:new_salt(),

    cfstore:save(?couch_atokens, {[
        {<<"_id">>, list_to_binary(AToken)},
        {<<"key">>, AUKey},
        {<<"salt">>, list_to_binary(Salt)},
        {<<"expires">>, list_to_binary(Expires)},
        {<<"scope">>, Scope}
    ]}),

    {ok, [
        {atoken, list_to_binary(AToken)},
        {opensalt, list_to_binary(Salt)},
        {scope, Scope}
    ]}.

check(AToken) ->
    case cfstore:get(?couch_atokens, AToken) of
        {ok, DocJson} ->
            {DocKVList} = DocJson,
            AUKey = proplists:get_value(<<"key">>, DocKVList),
            Salt = proplists:get_value(<<"salt">>, DocKVList),
            Scope = proplists:get_value(<<"scope">>, DocKVList, []),
            ExpiresBin = proplists:get_value(<<"expires">>, DocKVList, <<"0">>),
            Expires = binary_to_integer(ExpiresBin),

            Condition = ds_util:timestamp() < Expires
                andalso
                %% Check if AUKey still exists
                checkKey(AUKey),

            case Condition of
                false ->
                    %% TODO drop the doc
                    {error, "Invalid Token"};
                true ->
                    {ok, [
                        {aukey, AUKey},
                        {opensalt, Salt},
                        {scope, Scope},
                        {expires, Expires}
                    ]}
            end;
        {error, Error} -> {error, Error}
    end.

get_aukey({atoken, AToken}) ->
    case cfstore:get(?couch_atokens, AToken) of
        {ok, DocJson} ->
            {DocKVList} = DocJson,
            AUKey = proplists:get_value(<<"key">>, DocKVList),
            {ok, AUKey};
        {error, Error} -> {error, Error}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

checkKey(LeftAUKey) ->
    LeftAUKey =/= undefined
        andalso
        case aukey_server:get_aukey({aukey, LeftAUKey}) of
            {ok, _} -> true;
            _ -> false
        end.
