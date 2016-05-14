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

-module(incfstore_stream).
-author("epappas").

-behaviour(gen_stream).

-include("cloudfile.hrl").

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
    upload_ref, result, done = false, auth_key,
    file_name, file_key, ctype, ctransfer_encoding
}).

%%%===================================================================
%%% API
%%%===================================================================

init(Args) ->
    AuthKey = proplists:get_value("auth_key", Args),
    FileKey = proplists:get_value("file_key", Args),
    Filename = proplists:get_value("file_name", Args),
    CType = proplists:get_value("content_type", Args),
    CTransferEncoding = proplists:get_value("transfer_encoding", Args),

    %% Check if file exist, if yes, state the version of the doc
    Opts =
      case ?FILE_GET(FileKey) of
        {ok, FileKVList} ->
          case proplists:get_value(<<"_rev">>, FileKVList) of
            undefined -> [];
            Rev -> [{rev, Rev}]
          end;
        {error, not_found} -> []
      end,

    %% initiate attachmanet upload
    {ok, UploadRef} = ?FILE_INSTREAM(FileKey, Filename, Opts),

    {ok, #state{
        upload_ref = UploadRef,
        ctype = CType,
        ctransfer_encoding = CTransferEncoding,
        file_key = FileKey,
        file_name = Filename,
        auth_key = AuthKey
    }}.

on_data(undefined, Stream, #state{} = State) ->
    {ignore, Stream, State};

on_data(_Message, Stream, #state{done = true} = State) ->
    {ignore, Stream, State};

on_data(#cfmsg{body = Body, done = false} = _Message, Stream, #state{
    done = false, upload_ref = UploadRef
} = State) ->
    ok = cfstore:stream_attach(UploadRef, Body),

    {ignore, Stream, State};

on_data(#cfmsg{
        body = Body, done = true,
        md5 = MD5, sha = SHA, sha512 = SHA512,
        aes_key = AESKey, aes_iv = AESIV
    } = _Message,
    Stream,
    #state{
        done = false, upload_ref = UploadRef,
        ctype = CType,
        ctransfer_encoding = CTransferEncoding,
        file_key = FileKey,
        file_name = Filename,
        auth_key = AuthKey
} = State) ->

    ok = cfstore:stream_attach(UploadRef, Body),
    {ok, {Result}} = cfstore:stream_attach_done(UploadRef),

    Rev = proplists:get_value(<<"rev">>, Result),
    Id = proplists:get_value(<<"id">>, Result),

    % {ok, DocKVList} = ?FILE_GET(Id, Rev1),

    FileKeyBin = list_to_binary(FileKey),

    %% append meta info
    Doc = {[
        {<<"key">>, AuthKey},
        {<<"fileKey">>, FileKeyBin},
        {<<"filename">>, Filename},
        {<<"ctype">>, CType},
        {<<"ctransferEncoding">>, CTransferEncoding},
        {<<"created">>, time_util:timestamp()},
        {<<"md5">>, base64:encode(MD5)},
        {<<"sha">>, base64:encode(SHA)},
        {<<"sha512">>, base64:encode(SHA512)}
    ]},

    %% Commit the document
    {ok, ResultDoc} = ?FILE_DETAILS_SAVE(Id, Doc),

    %% Commit the notification document
    {ok, _} = ?NOTIFICATION_SAVE({[
        {<<"fileKey">>, FileKeyBin},
        {<<"filename">>, Filename},
        {<<"created">>, time_util:timestamp()},
        {<<"aes_iv">>, base64:encode(AESIV)},
        {<<"md5">>, base64:encode(MD5)},
        {<<"sha">>, base64:encode(SHA)},
        {<<"sha512">>, base64:encode(SHA512)}
    ]}),

    %% Commit the security details
    {ok, _} = ?FILE_SECRET_SAVE(<<FileKeyBin/binary, Rev/binary>>, {[{<<"aes_key">>, base64:encode(AESKey)},
        {<<"aes_iv">>, base64:encode(AESIV)},
        {<<"md5">>, base64:encode(MD5)},
        {<<"sha">>, base64:encode(SHA)},
        {<<"sha512">>, base64:encode(SHA512)},
        {<<"fileKey">>, FileKeyBin}]}),

    {ok, Stream, State#state{
        done = true, upload_ref = UploadRef, result = ResultDoc
    }}.

on_offer(undefined, Stream, #state{} = State) ->
    {undefined, Stream, State};

on_offer(_Message, Stream, #state{done = false} = State) ->
    {undefined, Stream, State};

on_offer(_Message, Stream, #state{
    done = true, result = ResultDoc
} = State) ->

    {ResultDoc, Stream, State}.

on_state(#state{} = _State, _Stream, StateData) ->
    {ok, StateData}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
