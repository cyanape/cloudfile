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

%%%===================================================================
%%% Tables/Views/DB Macros & records
%%%===================================================================

-define(couch_secrets, "erl_users_secrets").
-define(couch_file_secrets, "erl_files_secrets").
-define(couch_file_uploads, "erl_files_uploads").
-define(couch_file_details, "erl_files_details").
-define(couch_file_notification, "erl_file_notification").

%%%===================================================================
%%% Util Macros
%%%===================================================================

%%%===================================================================
%%% Stream Macros & Records
%%%===================================================================

-record(cfmsg, {
    body, file_key,
    done = false, md5 = undefined,
    sha = undefined, sha512 = undefined,
    aes_key = undefined, aes_iv = undefined
}).

-record(file_info, {
    file_key, md5 = undefined,
    sha = undefined, sha512 = undefined
}).

%%%===================================================================
%%% File Macros
%%%===================================================================

-define (FILE_OUTSTREAM(FileKey, FileName), begin
    case cfstore:fetch_attachment_stream(?couch_file_uploads, FileKey, FileName) of
        {ok, Attachmanet_StreamRef} -> {ok, Attachmanet_StreamRef};
        _ -> {error, not_found}
    end
end).

-define (FILE_INSTREAM(FileKey, FileName, Opts), begin
    case cfstore:attach(?couch_file_uploads, FileKey, {Filename, stream}, Opts) of
        {ok, FileUploadRef} -> {ok, FileUploadRef};
        _ -> {error, not_found}
    end
end).

-define (FILE_GET(FileKey), begin
    case cfstore:get(?couch_file_uploads, FileKey) of
        {ok, {FileInfoKVList}} -> {ok, FileInfoKVList};
        _ -> {error, not_found}
    end
end).

-define (FILE_GET(FileKey, Rev), begin
    case cfstore:get(?couch_file_uploads, FileKey, Rev) of
        {ok, {FileInfoKVList}} -> {ok, FileInfoKVList};
        _ -> {error, not_found}
    end
end).

-define (FILE_DETAILS(FileKey), begin
    case cfstore:get(?couch_file_details, FileKey) of
        {ok, {FileInfoKVList}} -> {ok, FileInfoKVList};
        _ -> {error, not_found}
    end
end).

-define (FILE_DETAILS(FileKey, Rev), begin
    case cfstore:get(?couch_file_details, FileKey, Rev) of
        {ok, {FileInfoKVList}} -> {ok, FileInfoKVList};
        _ -> {error, not_found}
    end
end).

-define (FILE_DETAILS_SAVE(Id, Doc, Rev), begin
    {ok, ResultDoc} = cfstore:save(?couch_file_details, Doc, [{<<"_id">>, Id}, {<<"_rev">>, Rev}])
end).

-define (FILE_DETAILS_SAVE(Id, Doc), begin
    {ok, ResultDoc} = cfstore:save(?couch_file_details, Doc, [{<<"_id">>, Id}])
end).

-define (FILE_SAVE(Id, Doc, Rev), begin
    {ok, ResultDoc} = cfstore:save(?couch_file_uploads, Doc, [{<<"_id">>, Id}, {<<"_rev">>, Rev}])
end).

-define (FILE_SAVE(Id, Doc), begin
    {ok, ResultDoc} = cfstore:save(?couch_file_uploads, Doc, [{<<"_id">>, Id}])
end).

-define (NOTIFICATION_SAVE(Doc), begin
    {ok, _} = cfstore:save(?couch_file_notification, Doc)
end).

-define (FILE_SECRET_SAVE(Id, Doc), begin
    {ok, _} = cfstore:save(?couch_file_secrets, Doc, [{<<"_id">>, Id}])
end).

%%%===================================================================
%%% HTTP Macros
%%%===================================================================

-define(HTTP_SERVER_NAME, <<"cloudfile">>).

-define(HTTP_ECHO(Status, Echo, Req),
    cowboy_req:reply(Status, [
        {<<"content-type">>, <<"application/json; charset=utf-8">>},
        {<<"server">>, ?HTTP_SERVER_NAME}
    ], Echo, Req)
).

-define(HTTP_ECHO(Status, CType, Echo, Req), begin
    case Echo of
        undefined ->
            cowboy_req:reply(Status, [
                {<<"content-type">>, CType},
                {<<"server">>, ?HTTP_SERVER_NAME}
            ], Req);
        _ ->
            cowboy_req:reply(Status, [
                {<<"content-type">>, CType},
                {<<"server">>, ?HTTP_SERVER_NAME}
            ], Echo, Req)
    end
end
).

-define(HTTP_CHUNKED_RESP(StreamFun, Req),
    cowboy_req:set_resp_body_fun(chunked, StreamFun, Req)
).

-define(HTTP_END_SUCCESS(Message, Req), {ok, ?HTTP_ECHO(200, jiffy:encode(Message), Req)}).

-define(HTTP_END_FAILURE(Code, Message, Req),
    {ok, ?HTTP_ECHO(Code, jiffy:encode({[
        {code, Code},
        {status, error},
        {error, Message}
    ]}), Req)}
).
