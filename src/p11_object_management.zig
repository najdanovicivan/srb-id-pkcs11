const std = @import("std");

const pkcs = @cImport({
    @cInclude("pkcs.h");
});

const pkcs_error = @import("pkcs_error.zig");
const object = @import("object.zig");
const session = @import("session.zig");

const PkcsError = pkcs_error.PkcsError;

pub export fn createObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = template;
    _ = count;
    _ = object_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn copyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
    new_object_handle: ?*pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = template;
    _ = count;
    _ = new_object_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn destroyObject(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getObjectSize(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    size: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = size;

    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn getAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: [*c]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    var has_attribute_sensitive = false;
    var has_attribute_type_invalid = false;
    var has_small_buffer = false;

    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    if (template == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (count == 0)
        return pkcs.CKR_ARGUMENTS_BAD;

    const selected_object = current_session.getObject(object_handle) catch |err|
        return pkcs_error.toRV(err);

    for (0..count) |i| {
        // TODO: Do error paths free memory?
        const object_attribute = selected_object.getAttribute(current_session.allocator, template.?[i].type) catch |err| {
            switch (err) {
                PkcsError.AttributeSensitive => {
                    has_attribute_sensitive = true;
                    continue;
                },
                PkcsError.AttributeTypeInvalid => {
                    template[i].ulValueLen = pkcs.CK_UNAVAILABLE_INFORMATION;
                    has_attribute_type_invalid = true;
                    continue;
                },
                else => return pkcs_error.toRV(err),
            }
        };
        defer object_attribute.deinit(current_session.allocator);

        if (template[i].pValue == null) {
            template[i].ulValueLen = object_attribute.value.len;
            continue;
        }

        const target_buffer: [*]u8 = @ptrCast(template[i].pValue.?);

        if (template[i].ulValueLen < object_attribute.value.len) {
            has_small_buffer = true;
            template[i].ulValueLen = pkcs.CK_UNAVAILABLE_INFORMATION;
            continue;
        }

        template[i].ulValueLen = object_attribute.value.len;
        std.mem.copyForwards(u8, target_buffer[0..template[i].ulValueLen], object_attribute.value);
    }

    if (has_attribute_sensitive)
        return pkcs.CKR_ATTRIBUTE_SENSITIVE;

    if (has_attribute_type_invalid)
        return pkcs.CKR_ATTRIBUTE_TYPE_INVALID;

    if (has_small_buffer)
        return pkcs.CKR_BUFFER_TOO_SMALL;

    return pkcs.CKR_OK;
}

pub export fn setAttributeValue(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handle: pkcs.CK_OBJECT_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    _ = session_handle;
    _ = object_handle;
    _ = template;
    _ = count;
    return pkcs.CKR_FUNCTION_NOT_SUPPORTED;
}

pub export fn findObjectsInit(
    session_handle: pkcs.CK_SESSION_HANDLE,
    template: ?[*]pkcs.CK_ATTRIBUTE,
    count: pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.None) catch |err|
        return pkcs_error.toRV(err);

    if (template == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    current_session.search_index = 0;

    const search_template = object.parseAttributes(current_session.allocator, template.?[0..count]) catch |err|
        return pkcs_error.toRV(err);

    current_session.findObjects(search_template) catch |err|
        return pkcs_error.toRV(err);

    current_session.operation = session.Operation.Search;

    return pkcs.CKR_OK;
}

pub export fn findObjects(
    session_handle: pkcs.CK_SESSION_HANDLE,
    object_handles: ?[*]pkcs.CK_OBJECT_HANDLE,
    max_object_count: pkcs.CK_ULONG,
    object_count: ?*pkcs.CK_ULONG,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Search) catch |err|
        return pkcs_error.toRV(err);

    if (object_handles == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (object_count == null)
        return pkcs.CKR_ARGUMENTS_BAD;

    if (current_session.found_objects == null)
        return pkcs.CKR_GENERAL_ERROR;

    if (current_session.found_objects.?.len < current_session.search_index) {
        object_count.?.* = 0;
        return pkcs.CKR_OK;
    }

    const remaining_objects: pkcs.CK_ULONG = current_session.found_objects.?.len - current_session.search_index;
    const objects_to_return = @min(remaining_objects, max_object_count);

    object_count.?.* = objects_to_return;

    std.mem.copyForwards(pkcs.CK_OBJECT_HANDLE, object_handles.?[0..max_object_count], current_session.found_objects.?[current_session.search_index .. current_session.search_index + objects_to_return]);

    current_session.search_index += objects_to_return;

    return pkcs.CKR_OK;
}

pub export fn findObjectsFinal(
    session_handle: pkcs.CK_SESSION_HANDLE,
) pkcs.CK_RV {
    const current_session = session.getSession(session_handle, false) catch |err|
        return pkcs_error.toRV(err);

    current_session.assertOperation(session.Operation.Search) catch |err|
        return pkcs_error.toRV(err);

    current_session.operation = session.Operation.None;

    return pkcs.CKR_OK;
}
