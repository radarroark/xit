pub const AddRemoteInput = struct {
    name: []const u8,
    url: []const u8,
};

pub const RemoveRemoteInput = struct {
    name: []const u8,
};

pub const RemoteCommand = union(enum) {
    list,
    add: AddRemoteInput,
    remove: RemoveRemoteInput,
};
