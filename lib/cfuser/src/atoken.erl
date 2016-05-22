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
    generate/2,
    check/2,
    store/3
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

generate({aukey, AUKey}, Scope) ->
    generate(#atoken_generate{
        aukey = AUKey, scope = [Scope],
        expires = ?Default_Atoken_Expiration
    }).

generate(#atoken_generate{aukey = AUKey, scope = Scope, expires = Expires}) ->

    AToken = srp:new_salt(),
    Salt = srp:new_salt(),

    % ?couch_atokens
    ATokenDoc = {[
        {<<"_id">>, list_to_binary(AToken)},
        {<<"key">>, AUKey},
        {<<"salt">>, list_to_binary(Salt)},
        {<<"expires">>, list_to_binary(Expires)},
        {<<"scope">>, Scope}
    ]},

    {ok, ATokenDoc}.

store(atoken, _Id, Doc) -> cfstore:save(?couch_atokens, Doc).

check(AUKey, AToken) ->
    case cfstore:get(?couch_atokens, AToken) of
        {error, Error} -> {error, Error};
        {ok, ATokenDoc} ->
            {ATokenKVList} = ATokenDoc,
            AUKey = proplists:get_value(<<"key">>, ATokenKVList),
            Salt = proplists:get_value(<<"salt">>, ATokenKVList),
            Scope = proplists:get_value(<<"scope">>, ATokenKVList, []),
            ExpiresBin = proplists:get_value(<<"expires">>, ATokenKVList, <<"0">>),
            Expires = binary_to_integer(ExpiresBin),

            %% Check if AUKey still exists
            Condition = ds_util:timestamp() < Expires andalso checkKey(AUKey),

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
            end
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

checkKey(LeftAUKey) ->
    LeftAUKey =/= undefined
        andalso
        case aukey:get(aukey, {aukey, LeftAUKey}) of
            {ok, _} -> true;
            _ -> false
        end.
