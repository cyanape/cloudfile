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
-module(cfuser).
-author("epappas").

%% API
-export([
    register/1,
    generate/2,
    getuser/1,
    updateprofile/2,
    encrypt/3,
    dencrypt/3
]).

-include("cfuser.hrl").

%%%===================================================================
%%% API
%%%===================================================================

register(Email) ->
    Version = ?User_SRP_Version, %% get User's Version
    UserRSABits = ?User_RSA_Bits, %% Define RSA bits
    UserPrimeBytes = ?User_Prime_Bytes, %% get Prime of user
    UserGenerator = ?User_Generator, %% get generator of user
    Factor = ?Factor,

    case ukey:check(Email) of
      {nonexist, {key, MD5Key}} ->

        %% Generate a User
        {ok, #ukey_generate_rsp{ukey = UKey}} =
          ukey:generate(#ukey_generate{
            email = Email, userPrimeBytes = UserPrimeBytes,
            userGenerator = UserGenerator,
            factor = Factor, version = Version,
            userRSABits = UserRSABits
          }),

        %% Generate an Open Key for this user
        {ok, #oukey_generate_rsp{oukey = OUKey, secret = Secret}} =
          oukey:generate(#oukey_generate{
            ukey = UKey, email = Email,
            userPrimeBytes = UserPrimeBytes,
            userGenerator = UserGenerator,
            factor = Factor, version = Version,
            userRSABits = UserRSABits
          }),

        %% Generate an Access Key for this Open Key
        {ok, #aukey_generate_rsp{aukey = AUKey, asecret = ASecret}} =
          aukey:generate(#aukey_generate{
            oukey = OUKey, userPrimeBytes = UserPrimeBytes,
            userGenerator = UserGenerator,
            factor = Factor, version = Version,
            userRSABits = UserRSABits
          }),

        %% Store primary email as both Alias & source
        cfstore:save(?couch_user_alias, {[
          {<<"_id">>, list_to_binary(MD5Key)},
          {<<"key">>, UKey},
          {<<"email">>, list_to_binary(Email)},
          {<<"alias">>, list_to_binary(Email)}
        ]}),

        {ok, [
          {email, list_to_binary(Email)},
          {oukey, OUKey},
          {secret, Secret},
          {aukey, AUKey},
          {asecret, ASecret}
        ]};
      _ -> {error, "Registration Failure"}
  end.

getuser(Ukey) -> doGetUser(Ukey).

updateprofile(Ukey, KeyValList) -> doUpdateProfile(Ukey, KeyValList).

encrypt(Ukey, IVec, Text) ->
  case cfstore:get(?couch_secrets, Ukey) of
    {ok, SecretJson} ->
      {SecretKVList} = SecretJson,
      SecretBin = proplists:get_value(<<"secret">>, SecretKVList),
      SecretList = binary_to_list(SecretBin),
      Secret = lists:sublist(SecretList, 8),

      IvacBin = list_to_binary(case is_binary(IVec) of
                                 false -> lists:sublist(IVec, 8);
                                 true -> lists:sublist(binary_to_list(IVec), 8)
                               end),
      TextChecked = case length(Text) rem 8 of
                      0 -> Text;
                      N -> Text ++ [" " || _S <- lists:seq(1, 8 - N)]
                    end,
      {ok, crypto:des_cbc_encrypt(Secret, IvacBin, TextChecked)};

    Error -> {error, Error}
  end.

dencrypt(Ukey, IVec, Text) ->
  case cfstore:get(?couch_secrets, Ukey) of
    {ok, SecretJson} ->
      {SecretKVList} = SecretJson,
      SecretBin = proplists:get_value(<<"secret">>, SecretKVList),
      SecretList = binary_to_list(SecretBin),
      Secret = lists:sublist(SecretList, 8),

      IvacBin = list_to_binary(case is_binary(IVec) of
                                 false -> lists:sublist(IVec, 8);
                                 true -> lists:sublist(binary_to_list(IVec), 8)
                               end),
      {ok, crypto:des_cbc_decrypt(Secret, IvacBin, Text)};

    Error -> {error, Error}
  end.

generate(oukey, Params) ->
  UKey = proplists:get_value(ukey, Params),
  Email = proplists:get_value(email, Params),

  {ok, #oukey_generate_rsp{oukey = OUKey, secret = Secret}} =
    oukey:generate(#oukey_generate{
      ukey = UKey, email = Email,
      userPrimeBytes = ?User_Prime_Bytes,
      userGenerator = ?User_Generator,
      factor = ?Factor, version = ?User_SRP_Version,
      userRSABits = ?User_RSA_Bits
    }),

  {ok, [
    {email, list_to_binary(Email)},
    {oukey, OUKey},
    {secret, Secret}
  ]};

generate(aukey, Params) ->
  OUKey = proplists:get_value(oukey, Params),

  {ok, #aukey_generate_rsp{aukey = AUKey, asecret = ASecret}} =
    aukey:generate(#aukey_generate{
      oukey = OUKey, userPrimeBytes = ?User_Prime_Bytes,
      userGenerator = ?User_Generator,
      factor = ?Factor, version = ?User_SRP_Version,
      userRSABits = ?User_RSA_Bits
    }),

  {ok, [
    {aukey, AUKey},
    {asecret, ASecret}
  ]};

generate(atoken, Params) ->
  AUKey = proplists:get_value(aukey, Params),
  Scope = proplists:get_value(scope, Params, []),
  Expires = proplists:get_value(expires, Params, integer_to_list(list_to_integer(?Default_Atoken_Expiration, 10) + ds_util:timestamp())),

  case atoken:generate(#atoken_generate{aukey = AUKey, scope = Scope, expires = Expires}) of
    {ok, ResultKVList} -> {ok, ResultKVList};
    Error -> {error, Error}
  end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

doGetUser(Ukey) ->
  case cfstore:get(?couch_users, Ukey) of
    {error, Error} -> {error, Error};
    {ok, UserJson} ->
      {UserKVList} = UserJson,
      {ok, UserKVList};
    Error -> {error, Error}
  end.

doUpdateProfile(Ukey, KeyValList) ->
  case cfstore:get(?couch_users, Ukey) of
    {error, Error} -> {error, Error};
    {ok, UserJson} ->
      {UserKVList} = UserJson,
      This_id = proplists:get_value(<<"_id">>, UserKVList),
      This_rev = proplists:get_value(<<"_rev">>, UserKVList),
      NewUserValList1 = lists:ukeymerge(1, KeyValList, UserKVList),
      NewUserValList2 = lists:ukeymerge(1, [
        {<<"_id">>, This_id},
        {<<"_rev">>, This_rev}
      ], NewUserValList1),

      case cfstore:save(?couch_users, {NewUserValList2}) of
        {error, Error} -> {error, Error};
        {ok, Result} -> {ok, Result};
        Error -> {error, Error}
      end;
    Error -> {error, Error}
  end.
