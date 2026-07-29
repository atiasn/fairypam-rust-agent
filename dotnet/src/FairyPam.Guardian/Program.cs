using FairyPam.Agent.Core;

namespace FairyPam.Guardian;

internal static class Program
{
    private static int Main()
    {
        Stream input = Console.OpenStandardInput();
        Stream output = Console.OpenStandardOutput();
        bool registered = false;
        ulong lastSequence = 0;

        try
        {
            while (GuardianWire.Read(input) is { } frame)
            {
                switch (frame.Type)
                {
                    case GuardianMessageType.Hello:
                        GuardianHello hello = GuardianWire.Decode<GuardianHello>(frame);
                        if (registered
                            || hello.SchemaVersion != 1
                            || hello.AgentPid <= 0
                            || hello.HeartbeatTimeoutMs is < 100 or > 5000)
                        {
                            return Fail(output, lastSequence, "guardian.hello_invalid");
                        }
                        registered = true;
                        GuardianWire.Write(output, GuardianMessageType.Ack, new GuardianAck(0));
                        break;
                    case GuardianMessageType.Heartbeat:
                        GuardianHeartbeat heartbeat = GuardianWire.Decode<GuardianHeartbeat>(frame);
                        if (!registered || heartbeat.Sequence <= lastSequence)
                        {
                            return Fail(output, heartbeat.Sequence, "guardian.sequence_invalid");
                        }
                        lastSequence = heartbeat.Sequence;
                        GuardianWire.Write(output, GuardianMessageType.Ack, new GuardianAck(lastSequence));
                        break;
                    case GuardianMessageType.ReleaseAll:
                        GuardianReleaseAll release = GuardianWire.Decode<GuardianReleaseAll>(frame);
                        if (!registered
                            || release.Sequence <= lastSequence
                            || string.IsNullOrWhiteSpace(release.ReasonCode))
                        {
                            return Fail(output, release.Sequence, "guardian.release_invalid");
                        }
                        lastSequence = release.Sequence;
                        // Slice 1 has no input adapter, so the only safe held set is empty.
                        GuardianWire.Write(output, GuardianMessageType.Ack, new GuardianAck(lastSequence));
                        break;
                    default:
                        return Fail(output, lastSequence, "guardian.input_not_available");
                }
            }
            return registered ? 0 : 2;
        }
        catch (AgentContractException)
        {
            return 2;
        }
        catch (IOException)
        {
            return 2;
        }
    }

    private static int Fail(Stream output, ulong sequence, string code)
    {
        GuardianWire.Write(output, GuardianMessageType.Error, new GuardianError(code, sequence));
        return 2;
    }
}
