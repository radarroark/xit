const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const DeprecatedFileReader = GenericReader(std.fs.File, std.posix.ReadError, std.fs.File.read);
pub fn deprecatedFileReader(file: std.fs.File) DeprecatedFileReader {
    return .{ .context = file };
}

pub const DeprecatedFileWriter = GenericWriter(std.fs.File, std.posix.WriteError, std.fs.File.write);
pub fn deprecatedFileWriter(file: std.fs.File) DeprecatedFileWriter {
    return .{ .context = file };
}

pub const DeprecatedArrayListWriterContext = struct {
    self: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
};
const AllocatorError = error{OutOfMemory};
fn appendWrite(context: DeprecatedArrayListWriterContext, m: []const u8) AllocatorError!usize {
    try context.self.appendSlice(context.allocator, m);
    return m.len;
}
pub const DeprecatedArrayListWriter = GenericWriter(DeprecatedArrayListWriterContext, AllocatorError, appendWrite);
pub fn deprecatedArrayListWriter(self: *std.ArrayList(u8), gpa: std.mem.Allocator) DeprecatedArrayListWriter {
    return .{ .context = .{ .self = self, .allocator = gpa } };
}

fn derpRead(context: *const anyopaque, buffer: []u8) anyerror!usize {
    const r: *std.Io.Reader = @ptrCast(@alignCast(@constCast(context)));
    return r.readSliceShort(buffer);
}
pub fn adaptToOldInterface(r: *std.Io.Reader) AnyReader {
    return .{ .context = r, .readFn = derpRead };
}

pub const AnyReader = @import("Io/DeprecatedReader.zig");
pub const Reader = std.Io.Reader;

pub const AnyWriter = @import("Io/DeprecatedWriter.zig");
pub const Writer = std.Io.Writer;

pub fn GenericReader(
    comptime Context: type,
    comptime ReadError: type,
    /// Returns the number of bytes read. It may be less than buffer.len.
    /// If the number of bytes read is 0, it means end of stream.
    /// End of stream is not an error condition.
    comptime readFn: fn (context: Context, buffer: []u8) ReadError!usize,
) type {
    return struct {
        context: Context,

        pub const Error = ReadError;
        pub const NoEofError = ReadError || error{
            EndOfStream,
        };

        pub inline fn read(self: Self, buffer: []u8) Error!usize {
            return readFn(self.context, buffer);
        }

        pub inline fn readAll(self: Self, buffer: []u8) Error!usize {
            return @errorCast(self.any().readAll(buffer));
        }

        pub inline fn readAtLeast(self: Self, buffer: []u8, len: usize) Error!usize {
            return @errorCast(self.any().readAtLeast(buffer, len));
        }

        pub inline fn readNoEof(self: Self, buf: []u8) NoEofError!void {
            return @errorCast(self.any().readNoEof(buf));
        }

        pub inline fn readAllArrayList(
            self: Self,
            array_list: *std.array_list.Managed(u8),
            max_append_size: usize,
        ) (error{StreamTooLong} || Allocator.Error || Error)!void {
            return @errorCast(self.any().readAllArrayList(array_list, max_append_size));
        }

        pub inline fn readAllArrayListAligned(
            self: Self,
            comptime alignment: ?Alignment,
            array_list: *std.array_list.AlignedManaged(u8, alignment),
            max_append_size: usize,
        ) (error{StreamTooLong} || Allocator.Error || Error)!void {
            return @errorCast(self.any().readAllArrayListAligned(
                alignment,
                array_list,
                max_append_size,
            ));
        }

        pub inline fn readAllAlloc(
            self: Self,
            allocator: Allocator,
            max_size: usize,
        ) (Error || Allocator.Error || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readAllAlloc(allocator, max_size));
        }

        pub inline fn readUntilDelimiterArrayList(
            self: Self,
            array_list: *std.array_list.Managed(u8),
            delimiter: u8,
            max_size: usize,
        ) (NoEofError || Allocator.Error || error{StreamTooLong})!void {
            return @errorCast(self.any().readUntilDelimiterArrayList(
                array_list,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiterAlloc(
            self: Self,
            allocator: Allocator,
            delimiter: u8,
            max_size: usize,
        ) (NoEofError || Allocator.Error || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readUntilDelimiterAlloc(
                allocator,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiter(
            self: Self,
            buf: []u8,
            delimiter: u8,
        ) (NoEofError || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readUntilDelimiter(buf, delimiter));
        }

        pub inline fn readUntilDelimiterOrEofAlloc(
            self: Self,
            allocator: Allocator,
            delimiter: u8,
            max_size: usize,
        ) (Error || Allocator.Error || error{StreamTooLong})!?[]u8 {
            return @errorCast(self.any().readUntilDelimiterOrEofAlloc(
                allocator,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiterOrEof(
            self: Self,
            buf: []u8,
            delimiter: u8,
        ) (Error || error{StreamTooLong})!?[]u8 {
            return @errorCast(self.any().readUntilDelimiterOrEof(buf, delimiter));
        }

        pub inline fn streamUntilDelimiter(
            self: Self,
            writer: anytype,
            delimiter: u8,
            optional_max_size: ?usize,
        ) (NoEofError || error{StreamTooLong} || @TypeOf(writer).Error)!void {
            return @errorCast(self.any().streamUntilDelimiter(
                writer,
                delimiter,
                optional_max_size,
            ));
        }

        pub inline fn skipUntilDelimiterOrEof(self: Self, delimiter: u8) Error!void {
            return @errorCast(self.any().skipUntilDelimiterOrEof(delimiter));
        }

        pub inline fn readByte(self: Self) NoEofError!u8 {
            return @errorCast(self.any().readByte());
        }

        pub inline fn readByteSigned(self: Self) NoEofError!i8 {
            return @errorCast(self.any().readByteSigned());
        }

        pub inline fn readBytesNoEof(
            self: Self,
            comptime num_bytes: usize,
        ) NoEofError![num_bytes]u8 {
            return @errorCast(self.any().readBytesNoEof(num_bytes));
        }

        pub inline fn readInt(self: Self, comptime T: type, endian: std.builtin.Endian) NoEofError!T {
            return @errorCast(self.any().readInt(T, endian));
        }

        pub inline fn readVarInt(
            self: Self,
            comptime ReturnType: type,
            endian: std.builtin.Endian,
            size: usize,
        ) NoEofError!ReturnType {
            return @errorCast(self.any().readVarInt(ReturnType, endian, size));
        }

        pub const SkipBytesOptions = AnyReader.SkipBytesOptions;

        pub inline fn skipBytes(
            self: Self,
            num_bytes: u64,
            comptime options: SkipBytesOptions,
        ) NoEofError!void {
            return @errorCast(self.any().skipBytes(num_bytes, options));
        }

        pub inline fn isBytes(self: Self, slice: []const u8) NoEofError!bool {
            return @errorCast(self.any().isBytes(slice));
        }

        pub inline fn readStruct(self: Self, comptime T: type) NoEofError!T {
            return @errorCast(self.any().readStruct(T));
        }

        pub inline fn readStructEndian(self: Self, comptime T: type, endian: std.builtin.Endian) NoEofError!T {
            return @errorCast(self.any().readStructEndian(T, endian));
        }

        pub const ReadEnumError = NoEofError || error{
            /// An integer was read, but it did not match any of the tags in the supplied enum.
            InvalidValue,
        };

        pub inline fn readEnum(
            self: Self,
            comptime Enum: type,
            endian: std.builtin.Endian,
        ) ReadEnumError!Enum {
            return @errorCast(self.any().readEnum(Enum, endian));
        }

        pub inline fn any(self: *const Self) AnyReader {
            return .{
                .context = @ptrCast(&self.context),
                .readFn = typeErasedReadFn,
            };
        }

        const Self = @This();

        fn typeErasedReadFn(context: *const anyopaque, buffer: []u8) anyerror!usize {
            const ptr: *const Context = @ptrCast(@alignCast(context));
            return readFn(ptr.*, buffer);
        }

        /// Helper for bridging to the new `Reader` API while upgrading.
        pub fn adaptToNewApi(self: *const Self, buffer: []u8) Adapter {
            return .{
                .derp_reader = self.*,
                .new_interface = .{
                    .buffer = buffer,
                    .vtable = &.{ .stream = Adapter.stream },
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        pub const Adapter = struct {
            derp_reader: Self,
            new_interface: Reader,
            err: ?Error = null,

            fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
                const a: *@This() = @alignCast(@fieldParentPtr("new_interface", r));
                const buf = limit.slice(try w.writableSliceGreedy(1));
                const n = a.derp_reader.read(buf) catch |err| {
                    a.err = err;
                    return error.ReadFailed;
                };
                if (n == 0) return error.EndOfStream;
                w.advance(n);
                return n;
            }
        };
    };
}

pub fn GenericWriter(
    comptime Context: type,
    comptime WriteError: type,
    comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const Error = WriteError;

        pub inline fn write(self: Self, bytes: []const u8) Error!usize {
            return writeFn(self.context, bytes);
        }

        pub inline fn writeAll(self: Self, bytes: []const u8) Error!void {
            return @errorCast(self.any().writeAll(bytes));
        }

        pub inline fn print(self: Self, comptime format: []const u8, args: anytype) Error!void {
            return @errorCast(self.any().print(format, args));
        }

        pub inline fn writeByte(self: Self, byte: u8) Error!void {
            return @errorCast(self.any().writeByte(byte));
        }

        pub inline fn writeByteNTimes(self: Self, byte: u8, n: usize) Error!void {
            return @errorCast(self.any().writeByteNTimes(byte, n));
        }

        pub inline fn writeBytesNTimes(self: Self, bytes: []const u8, n: usize) Error!void {
            return @errorCast(self.any().writeBytesNTimes(bytes, n));
        }

        pub inline fn writeInt(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeInt(T, value, endian));
        }

        pub inline fn writeStruct(self: Self, value: anytype) Error!void {
            return @errorCast(self.any().writeStruct(value));
        }

        pub inline fn writeStructEndian(self: Self, value: anytype, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeStructEndian(value, endian));
        }

        pub inline fn any(self: *const Self) AnyWriter {
            return .{
                .context = @ptrCast(&self.context),
                .writeFn = typeErasedWriteFn,
            };
        }

        fn typeErasedWriteFn(context: *const anyopaque, bytes: []const u8) anyerror!usize {
            const ptr: *const Context = @ptrCast(@alignCast(context));
            return writeFn(ptr.*, bytes);
        }

        /// Helper for bridging to the new `Writer` API while upgrading.
        pub fn adaptToNewApi(self: *const Self, buffer: []u8) Adapter {
            return .{
                .derp_writer = self.*,
                .new_interface = .{
                    .buffer = buffer,
                    .vtable = &.{ .drain = Adapter.drain },
                },
            };
        }

        pub const Adapter = struct {
            derp_writer: Self,
            new_interface: Writer,
            err: ?Error = null,

            fn drain(w: *std.io.Writer, data: []const []const u8, splat: usize) std.io.Writer.Error!usize {
                _ = splat;
                const a: *@This() = @alignCast(@fieldParentPtr("new_interface", w));
                const buffered = w.buffered();
                if (buffered.len != 0) return w.consume(a.derp_writer.write(buffered) catch |err| {
                    a.err = err;
                    return error.WriteFailed;
                });
                return a.derp_writer.write(data[0]) catch |err| {
                    a.err = err;
                    return error.WriteFailed;
                };
            }
        };
    };
}
