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

-define(CACHE_TABLE, srp_session_tb).

-define(Default_Atoken_Expiration, integer_to_list(30 * 24 * 60 * 60 * 1000)). %% 30days in ms
-define(User_RSA_Bits, 2048).
-define(User_Prime_Bytes, 256).
-define(User_Generator, 2).
-define(User_SRP_Version, '6a').
-define(Factor, 20).
-define(Scope_all, [
    <<"all">>, <<"list_panel">>, <<"change_pass">>,
    <<"delete_access_keys">>, <<"list_access_keys">>,
    <<"list_settings">>, <<"create_access_keys">>,
    <<"edit_settings">>, <<"list_timeline">>,
    <<"edit_timeline">>, <<"post_timeline">>,
    <<"delete_timeline">>, <<"edit_profile">>,
    <<"delete_profile">>, <<"add_photo">>,
    <<"add_billing">>, <<"remove_billing">>,
    <<"download_files">>, <<"upload_files">>,
    <<"create_dir">>, <<"delete_dir">>,
    <<"use_rsa">>, <<"use_srp">>
]).

-define(couch_users, "erl_cloudfile_users").
-define(couch_md5keys, "erl_cloudfile_md5keys").
-define(couch_oukeys, "erl_cloudfile_oukeys").
-define(couch_aukeys, "erl_cloudfile_aukeys").
-define(couch_salts, "erl_cloudfile_salts").
-define(couch_secrets, "erl_cloudfile_secrets").
-define(couch_rsa, "erl_cloudfile_rsa").
-define(couch_user_alias, "erl_cloudfile_alias").
-define(couch_atokens, "erl_cloudfile_atokens").

-define(couch_oukeys_design, "erl_cloudfile_oukeys_design").
-define(couch_oukeys_design_view, "erl_cloudfile_oukeys_design_by_ukey_view").
-define(couch_aukeys_design, "erl_cloudfile_aukeys_design").
-define(couch_aukeys_design_view, "erl_cloudfile_aukeys_design_by_oukey_view").

-record(ukey_generate, {email, userPrimeBytes, userGenerator, factor, version, userRSABits}).
-record(oukey_generate, {ukey, userPrimeBytes, userGenerator, factor, version, userRSABits}).
-record(aukey_generate, {oukey, userPrimeBytes, userGenerator, factor, version, userRSABits}).
-record(atoken_generate, {aukey, expires, scope = []}).

-record(ukey_generate_rsp, {email, ukey, hash_key, user_doc, salt_doc, secret_doc, rsa_doc, md5_doc}).
-record(oukey_generate_rsp, {oukey, secret, oukey_doc, salt_doc, secret_doc, rsa_doc}).
-record(aukey_generate_rsp, {aukey, asecret, aukey_doc, salt_doc, secret_doc, rsa_doc}).
-record(atoken_rsp, {aukey, opensalt, scope, expires}).
