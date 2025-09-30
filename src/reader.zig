const std = @import("std");
extern "c" fn calloc(num: usize, size: usize) *anyopaque;
extern "c" fn free(ptr: ?*anyopaque) void;

const atr = @import("atr.zig");
const pkcs = @import("pkcs.zig").pkcs;
const state = @import("state.zig");
const sc = @import("smart-card_lib.zig").sc;

const PkcsError = @import("pkcs_error.zig").PkcsError;

var next_reader_id: pkcs.CK_SLOT_ID = 1;

pub var reader_states: std.AutoHashMap(pkcs.CK_SLOT_ID, ReaderState) = undefined;

pub var lock = std.Thread.RwLock{};

pub const UserType = enum {
    None,
    User,
    SecurityOfficer,
};

pub const ReaderState = struct {
    name: []const u8,
    active: bool,
    card_present: bool,
    recognized: bool,
    user_type: UserType,

    pub fn refreshCardPresent(self: *ReaderState, smart_card_context_handle: sc.SCARDHANDLE) PkcsError!void {
        var card_handle: sc.SCARDHANDLE = 0;
        var active_protocol: sc.DWORD = 0;

        const r = sc.SCardConnect(
            smart_card_context_handle,
            self.name.ptr,
            sc.SCARD_SHARE_SHARED,
            sc.SCARD_PROTOCOL_T0 | sc.SCARD_PROTOCOL_T1,
            &card_handle,
            &active_protocol,
        );

        const SCARD_E_NO_SMARTCARD : i32 = @bitCast(sc.SCARD_E_NO_SMARTCARD);
        const SCARD_W_UNPOWERED_CARD : i32 = @bitCast(sc.SCARD_W_UNPOWERED_CARD);
        const SCARD_W_UNRESPONSIVE_CARD : i32 = @bitCast(sc.SCARD_W_UNRESPONSIVE_CARD);
        const SCARD_E_READER_UNAVAILABLE : i32 = @bitCast(sc.SCARD_E_READER_UNAVAILABLE);

        switch (r) {
            sc.SCARD_S_SUCCESS => {
                var card_state: sc.DWORD = 0;
                var card_protocol: sc.DWORD = 0;

                var card_atr_len: sc.DWORD = 0;
                var reader_name_len: sc.DWORD = 0;

                _ = sc.SCardStatus(card_handle, null, &reader_name_len, &card_state, &card_protocol, null, &card_atr_len);

                const reader_name_c =  calloc(reader_name_len, @sizeOf(c_char));
                const card_atr_c =  calloc(card_atr_len, @sizeOf(c_char));

                _ = sc.SCardStatus(card_handle, @ptrCast(reader_name_c), &reader_name_len, &card_state, &card_protocol, @ptrCast(card_atr_c), &card_atr_len);


                var card_atr: [*c]u8 = @ptrCast(reader_name_c);
                //var reader_name: [*c]u8 = @ptrCast(reader_name_c);

                defer free(reader_name_c);
                defer free(card_atr_c);

                self.card_present = true;
                _ = sc.SCardDisconnect(card_handle, sc.SCARD_LEAVE_CARD);

                self.recognized = atr.validATR(card_atr[0..card_atr_len]);
            },
            SCARD_E_NO_SMARTCARD => {
                self.card_present = false;
            },
            SCARD_W_UNPOWERED_CARD, SCARD_W_UNRESPONSIVE_CARD, SCARD_E_READER_UNAVAILABLE => return PkcsError.DeviceError,
            else => return PkcsError.GeneralError,
        }
    }

    pub fn writeShortName(self: *const ReaderState, output: []u8) void {
        const open_index = std.mem.indexOfScalar(u8, self.name, '[');
        const close_index = std.mem.indexOfScalar(u8, self.name, ']');

        if (open_index == null or close_index == null or close_index.? <= open_index.?) {
            const len = @min(self.name.len, output.len);
            @memcpy(output[0..len], self.name[0..len]);
            if (len < output.len) output[len] = 0;
            return;
        }

        const before = self.name[0..open_index.?];
        const after = self.name[(close_index.? + 1)..];

        const trimmed_before = std.mem.trimRight(u8, before, " ");
        const trimmed_after = std.mem.trimLeft(u8, after, " ");

        var idx: usize = 0;

        if (idx + trimmed_before.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_before.len], trimmed_before);
            idx += trimmed_before.len;
        }

        if (trimmed_after.len > 0 and idx < output.len) {
            output[idx] = ' ';
            idx += 1;
        }

        if (idx + trimmed_after.len <= output.len) {
            @memcpy(output[idx..][0..trimmed_after.len], trimmed_after);
            idx += trimmed_after.len;
        }

        if (idx < output.len)
            output[idx] = 0;
    }
};

pub fn refreshStatuses(allocator: std.mem.Allocator, smart_card_context_handle: sc.SCARDHANDLE) PkcsError!void {

    var readers: sc.DWORD = 0;

    const rv0 = sc.SCardListReaders(
        smart_card_context_handle,
        null,
        null,
        &readers,
    );

    if (rv0 != sc.SCARD_S_SUCCESS and rv0 != sc.SCARD_E_NO_READERS_AVAILABLE) {
        if(rv0 == sc.SCARD_E_NO_MEMORY)
            return PkcsError.HostMemory;

        return PkcsError.GeneralError;
    }

    const readers_multi_string_c = calloc(readers, @sizeOf(c_char));
    const rv1 = sc.SCardListReaders(
        smart_card_context_handle,
        null,
        @ptrCast(readers_multi_string_c),
        &readers,
    );

    const readers_multi_string: [*c]u8 = @ptrCast(readers_multi_string_c);

    if (rv1 != sc.SCARD_S_SUCCESS and rv1 != sc.SCARD_E_NO_READERS_AVAILABLE) {
        if(rv1 == sc.SCARD_E_NO_MEMORY)
            return PkcsError.HostMemory;

        return PkcsError.GeneralError;
    }

    defer free(readers_multi_string_c);

    resetStates();

    if (rv1 != sc.SCARD_E_NO_READERS_AVAILABLE) {
        const reader_names = parseMultiString(allocator, readers_multi_string) catch
            return PkcsError.GeneralError;

        for (reader_names) |reader_name| {
            addIfNotExists(allocator, reader_name) catch
                return PkcsError.GeneralError;
        }
    }

    var reader_iterator = reader_states.iterator();
    while (reader_iterator.next()) |reader_state_entry| {
        if (!reader_state_entry.value_ptr.active)
            continue;

        try reader_state_entry.value_ptr.*.refreshCardPresent(smart_card_context_handle);
    }
}

fn addIfNotExists(allocator: std.mem.Allocator, reader_name: [*:0]const u8) std.mem.Allocator.Error!void {
    const reader_name_slice = std.mem.sliceTo(reader_name, 0);

    var iter = reader_states.iterator();
    while (iter.next()) |entry| {
        if (std.mem.eql(u8, entry.value_ptr.name, reader_name_slice)) {
            entry.value_ptr.*.active = true;
            return;
        }
    }

    const allocated_name = try allocator.allocSentinel(u8, reader_name_slice.len, 0);

    std.mem.copyForwards(u8, allocated_name, reader_name_slice);
    try reader_states.put(
        next_reader_id,
        ReaderState{
            .name = allocated_name,
            .active = true,
            .card_present = false,
            .recognized = false,
            .user_type = UserType.None,
        },
    );

    next_reader_id += 1;
}

fn resetStates() void {
    var it = reader_states.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.active = false;
        entry.value_ptr.*.card_present = false;
    }
}

fn parseMultiString(allocator: std.mem.Allocator, input: [*:0]const u8) std.mem.Allocator.Error![][:0]const u8 {
    var list = std.ArrayList([:0]const u8){};
    errdefer list.deinit(allocator);

    var i: usize = 0;
    while (true) {
        const start = input + i;
        const len = std.mem.len(start);

        if (len == 0)
            break;

        const slice = input[i .. i + len :0];
        try list.append(allocator, slice);

        i += len + 1;
    }

    return try list.toOwnedSlice(allocator);
}

pub fn setUserType(slot_id: pkcs.CK_SLOT_ID, user_type: UserType) void {
    lock.lock();
    defer lock.unlock();

    const reader_entry = reader_states.getPtr(slot_id);
    if (reader_entry == null)
        return;

    reader_entry.?.*.user_type = user_type;
}

pub fn getUserType(slot_id: pkcs.CK_SLOT_ID) UserType {
    lock.lockShared();
    defer lock.unlockShared();

    const reader_entry = reader_states.get(slot_id);
    if (reader_entry == null)
        return UserType.None;

    return reader_entry.?.user_type;
}
