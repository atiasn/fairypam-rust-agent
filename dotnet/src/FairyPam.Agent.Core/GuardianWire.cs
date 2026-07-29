using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FairyPam.Agent.Core;

public enum GuardianMessageType : ushort
{
    Hello = 1,
    Heartbeat = 2,
    RegisterIntent = 3,
    CommitHolds = 4,
    ReleaseAll = 5,
    EmergencyStop = 6,
    Ack = 100,
    Error = 101,
}

public sealed record GuardianFrame(GuardianMessageType Type, byte[] Payload);

public sealed record GuardianHello(
    [property: JsonPropertyName("agent_pid")] int AgentPid,
    [property: JsonPropertyName("heartbeat_timeout_ms")] int HeartbeatTimeoutMs,
    [property: JsonPropertyName("schema_version")] int SchemaVersion);

public sealed record GuardianHeartbeat(
    [property: JsonPropertyName("sequence")] ulong Sequence);

public sealed record GuardianReleaseAll(
    [property: JsonPropertyName("reason_code")] string ReasonCode,
    [property: JsonPropertyName("sequence")] ulong Sequence);

public sealed record GuardianAck(
    [property: JsonPropertyName("sequence")] ulong Sequence);

public sealed record GuardianError(
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("sequence")] ulong Sequence);

public static class GuardianWire
{
    public const int MaximumPayloadBytes = 64 * 1024;
    private const int HeaderBytes = 12;
    private const ushort ProtocolVersion = 1;
    private const uint Magic = 0x44475046; // FPGD in little-endian byte order.

    public static GuardianFrame? Read(Stream stream)
    {
        byte[] header = new byte[HeaderBytes];
        int first = stream.ReadByte();
        if (first == -1)
        {
            return null;
        }
        header[0] = (byte)first;
        ReadExactly(stream, header.AsSpan(1));

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(4));
        GuardianMessageType type = (GuardianMessageType)BinaryPrimitives.ReadUInt16LittleEndian(
            header.AsSpan(6));
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8));
        if (magic != Magic
            || version != ProtocolVersion
            || !Enum.IsDefined(type)
            || length > MaximumPayloadBytes)
        {
            throw new AgentContractException("guardian.frame_invalid", "Guardian frame is invalid.");
        }

        byte[] payload = new byte[checked((int)length)];
        ReadExactly(stream, payload);
        return new(type, payload);
    }

    public static T Decode<T>(GuardianFrame frame)
    {
        T value;
        try
        {
            value = JsonSerializer.Deserialize<T>(frame.Payload, StrictJson.Options)
                ?? throw new AgentContractException("guardian.payload_invalid", "Guardian payload is empty.");
        }
        catch (JsonException error)
        {
            throw new AgentContractException("guardian.payload_invalid", error.Message);
        }
        if (!frame.Payload.AsSpan().SequenceEqual(StrictJson.Canonicalize(value)))
        {
            throw new AgentContractException("guardian.payload_not_canonical", "Guardian payload is not canonical.");
        }
        return value;
    }

    public static void Write<T>(Stream stream, GuardianMessageType type, T payload)
    {
        if (!Enum.IsDefined(type))
        {
            throw new AgentContractException("guardian.type_invalid", "Guardian message type is invalid.");
        }
        byte[] json = StrictJson.Canonicalize(payload);
        if (json.Length > MaximumPayloadBytes)
        {
            throw new AgentContractException("guardian.payload_too_large", "Guardian payload is too large.");
        }

        Span<byte> header = stackalloc byte[HeaderBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(header, Magic);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], ProtocolVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], (ushort)type);
        BinaryPrimitives.WriteUInt32LittleEndian(header[8..], (uint)json.Length);
        stream.Write(header);
        stream.Write(json);
        stream.Flush();
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        while (!buffer.IsEmpty)
        {
            int read = stream.Read(buffer);
            if (read == 0)
            {
                throw new AgentContractException("guardian.frame_truncated", "Guardian frame is truncated.");
            }
            buffer = buffer[read..];
        }
    }
}
