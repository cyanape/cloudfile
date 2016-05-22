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
-module(srp).
-author("epappas").

%% API
-export([
    begin_srp/1,
    verifier/3,
    derived_key/2,
    derived_key/4,
    compute_key/3,
    prime/2,
    new_salt/0
]).

%%%===================================================================
%%% API
%%%===================================================================

verifier(Generator, DerivedKey, Prime) -> crypto:mod_pow(Generator, DerivedKey, Prime).

derived_key(Salt, Username, Password, Factor) ->
    derived_key(Salt, list_to_binary(hashPass(Password, Username, Factor))).

derived_key(Salt, Hashed) -> crypto:hash(sha256, [Salt, Hashed]).

prime(UserPrimeBytes, UserGenerator) -> crypto:dh_generate_parameters(UserPrimeBytes, UserGenerator).

new_salt() -> crypto_util:uuid().

%% accepts: {email, Email} | {oukey, OUKey} | {ukey, UKey},
%% gives:
%% {ok, {[
%%   {sesRef, Ref},
%%   {salt, Salt},
%%   {privKey, PrivKey}, b
%%   {pubKey, PubKey}, B
%%   {prime, Prime},
%%   {generator, Generator},
%%   {version, Version},
%%   {verifier, Verifier} v = g^x
%% ]}}
begin_srp({email, Email}) ->
    {ok, UKey} = ukey:get_ukey({email, Email}),
    generate_srp({ukey, UKey});
begin_srp({oukey, OUKey}) ->
    {ok, SRPDoc} = oukey:get(secrets, {oukey, OUKey}),
    generate_srp(SRPDoc);
begin_srp({aukey, AUKey}) ->
    {ok, SRPDoc} = aukey:get(secrets, {aukey, AUKey}),
    generate_srp(SRPDoc);
begin_srp({ukey, UKey}) ->
    {ok, SRPDoc} = ukey:get(secrets, {ukey, UKey}),
    generate_srp(SRPDoc).

%% [
%%   {privKey, PrivKey},
%%   {pubKey, PubKey},
%%   {prime, Prime},
%%   {generator, Generator},
%%   {version, Version},
%%   {verifier, Verifier}
%% ]
compute_key(server, {clientPub, ClientPub}, SrpSesList) ->
    PrivKey = proplists:get_value(<<"privKey">>, SrpSesList),
    PubKey = proplists:get_value(<<"pubKey">>, SrpSesList),
    Prime = proplists:get_value(<<"prime">>, SrpSesList),
    Generator = proplists:get_value(<<"generator">>, SrpSesList),
    Version = proplists:get_value(<<"version">>, SrpSesList),
    Verifier = proplists:get_value(<<"verifier">>, SrpSesList),

    SKey = crypto:compute_key(srp, ClientPub, {PubKey, PrivKey}, {host, [Verifier, Prime, Version]}),

    {ok, SKey};

%% [
%%   {privKey, PrivKey},
%%   {pubKey, PubKey},
%%   {derivedKey, DerivedKey},
%%   {prime, Prime},
%%   {generator, Generator},
%%   {version, Version}
%% ]
compute_key(client, {serverPub, ServerPub}, SrpSesList) ->
    PrivKey = proplists:get_value(<<"privKey">>, SrpSesList),
    PubKey = proplists:get_value(<<"pubKey">>, SrpSesList),
    DerivedKey = proplists:get_value(<<"derivedKey">>, SrpSesList),
    Prime = proplists:get_value(<<"prime">>, SrpSesList),
    Generator = proplists:get_value(<<"generator">>, SrpSesList),
    Version = proplists:get_value(<<"version">>, SrpSesList),

    SKey = crypto:compute_key(srp, ServerPub, {PubKey, PrivKey}, {user, [DerivedKey, Prime, Generator, Version]}),

    {ok, SKey}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

generate_srp({SRPEssentialsKVList}) ->
    Ref = crypto_util:uuid(),
    Salt = base64:decode(proplists:get_value(<<"srpsalt">>, SRPEssentialsKVList)), %% get salt of user
    Version = binary_to_atom(proplists:get_value(<<"version">>, SRPEssentialsKVList), utf8), %% get User's Version
    Verifier = base64:decode(proplists:get_value(<<"verifier">>, SRPEssentialsKVList)), %% Get User's Verifier
    UserPrimeBytes = proplists:get_value(<<"userPrimeBytes">>, SRPEssentialsKVList), %% get Prime of user
    UserGenerator = proplists:get_value(<<"userGenerator">>, SRPEssentialsKVList), %% get generator of user
    PrivKey = base64:decode(proplists:get_value(<<"privKey">>, SRPEssentialsKVList)), %% get User's Private

    %% Prime & Generator --> Bin
    [Prime, Generator] = prime(UserPrimeBytes, UserGenerator),
    %% PubKey = Bin,
    {PubKey, PrivKey} = crypto:generate_key(srp, {user, [Generator, Prime, Version]}, PrivKey),

    {ok, [
        {sesRef, base64:encode(Ref)},
        {salt, base64:encode(Salt)},
        {privKey, base64:encode(PrivKey)},
        {pubKey, base64:encode(PubKey)},
        {prime, base64:encode(Prime)},
        {generator, Generator},
        {version, Version},
        {verifier, base64:encode(Verifier)}
    ]}.

hashPass(Password, Salt, 0) ->
    crypto_util:hashPass(lists:concat([Password, Salt]));

hashPass(Password, Salt, Factor) when (Factor rem 2) > 0 ->
    hashPass(crypto_util:hashPass(lists:concat([Password, Salt])), Salt, Factor - 1);

hashPass(Password, Salt, Factor) ->
    hashPass(crypto_util:hashPass(lists:concat([Salt, Password])), Salt, Factor - 1).

bin_to_num(Bin) -> base64:encode(Bin).
