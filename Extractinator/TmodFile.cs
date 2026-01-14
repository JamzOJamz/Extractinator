using System.IO.Compression;
using JetBrains.Annotations;

namespace Extractinator;

/// <summary>
///     Represents a TMOD file and provides methods to read its contents.
/// </summary>
[PublicAPI]
public class TmodFile : IDisposable
{
    private const int MagicHeaderLength = 4;
    private const int Sha1HashLength = 20;
    private const int SignatureLength = 256;

    private readonly FileStream _fileStream;
    private readonly BinaryReader _reader;
    private bool _disposed;

    private TmodFile(string filePath)
    {
        try
        {
            _fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
            _reader = new BinaryReader(_fileStream);

            ValidateMagicHeader();
            TmlVersion = _reader.ReadString();
            Sha1Hash = ReadAndValidateHash();
            Signature = ReadAndValidateSignature();

            // We ignore the 4-byte data length field (unused)
            _ = _reader.ReadInt32();

            Name = _reader.ReadString();
            Version = new Version(_reader.ReadString());

            LoadFileTable();
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    ///     tModLoader version stored in the file header.
    /// </summary>
    public string TmlVersion { get; }

    /// <summary>
    ///     SHA-1 hash of the mod file stored in the file header.
    ///     TODO: Implement verification to compute the SHA-1 of the mod contents and compare it to this value.
    /// </summary>
    public byte[] Sha1Hash { get; }

    /// <summary>
    ///     Digital signature of the mod file.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    ///     Name of the mod.
    /// </summary>
    public string Name { get; }

    /// <summary>
    ///     Version of the mod.
    /// </summary>
    public Version Version { get; }

    private Dictionary<string, FileEntry> Files { get; } = new();

    public void Dispose()
    {
        if (_disposed)
            return;

        _reader.Dispose();
        _fileStream.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>
    ///     Gets all file entries in the TMOD archive.
    /// </summary>
    /// <returns>A collection of all file entries.</returns>
    public IEnumerable<FileEntry> GetFileEntries() => Files.Values;

    /// <summary>
    ///     Gets the names of all files in the TMOD archive.
    /// </summary>
    /// <returns>A collection of all file names.</returns>
    public IEnumerable<string> GetFileNames() => Files.Keys;

    /// <summary>
    ///     Opens a TMOD file for reading.
    /// </summary>
    /// <param name="filePath">Path to the TMOD file.</param>
    /// <returns>A new TmodFile instance.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the file doesn't exist.</exception>
    public static TmodFile Open(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"TMod file not found: {filePath}");

        return new TmodFile(filePath);
    }

    /// <summary>
    ///     Extracts a file from the TMOD archive.
    /// </summary>
    /// <param name="fileName">Name of the file to extract.</param>
    /// <returns>The extracted file data.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the file doesn't exist in the archive.</exception>
    public byte[] Extract(string fileName)
    {
        if (!Files.TryGetValue(fileName, out var fileEntry))
            throw new FileNotFoundException($"File not found in TMOD archive: {fileName}");

        return ExtractEntry(fileEntry);
    }

    /// <summary>
    ///     Extracts the mod's main assembly DLL.
    /// </summary>
    /// <param name="fileName">The name of the extracted assembly file.</param>
    /// <returns>The mod assembly file data.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the assembly doesn't exist in the archive.</exception>
    public byte[] ExtractAssembly(out string fileName)
    {
        fileName = $"{Name}.dll";
        return Extract(fileName);
    }

    private byte[] ExtractEntry(FileEntry fileEntry)
    {
        _fileStream.Position = fileEntry.Offset;
        var compressedData = _reader.ReadBytes(fileEntry.CompressedLength);

        // If the file is not compressed (compressed length == uncompressed length), returns the data as is
        if (fileEntry.CompressedLength == fileEntry.Length)
            return compressedData;

        return DecompressData(compressedData, fileEntry.Length);
    }

    private void ValidateMagicHeader()
    {
        var magic = _reader.ReadBytes(MagicHeaderLength);

        if (magic.Length != MagicHeaderLength ||
            magic[0] != 0x54 || // 'T'
            magic[1] != 0x4D || // 'M'
            magic[2] != 0x4F || // 'O'
            magic[3] != 0x44) // 'D'
        {
            throw new InvalidDataException(
                $"Invalid TMOD file: magic header not found! Expected 'TMOD', got: {BitConverter.ToString(magic)}");
        }
    }

    private byte[] ReadAndValidateHash()
    {
        var sha1Hash = _reader.ReadBytes(Sha1HashLength);

        if (sha1Hash.Length != Sha1HashLength)
            throw new InvalidDataException("Invalid TMOD file: unable to read SHA-1 hash.");

        return sha1Hash;
    }

    private byte[] ReadAndValidateSignature()
    {
        var signature = _reader.ReadBytes(SignatureLength);

        if (signature.Length != SignatureLength)
            throw new InvalidDataException("Invalid TMOD file: unable to read signature.");

        return signature;
    }

    private void LoadFileTable()
    {
        var fileCount = _reader.ReadInt32();
        var fileTable = new FileEntry[fileCount];
        var offset = 0;

        for (var i = 0; i < fileCount; i++)
        {
            var fileEntry = new FileEntry(
                _reader.ReadString(),
                offset,
                _reader.ReadInt32(),
                _reader.ReadInt32());

            fileTable[i] = fileEntry;
            Files[fileEntry.Name] = fileEntry;
            offset += fileEntry.CompressedLength;
        }

        AdjustFileOffsets(fileTable);
    }

    private void AdjustFileOffsets(FileEntry[] fileTable)
    {
        var fileStartPosition = (int)_fileStream.Position;

        foreach (var fileEntry in fileTable)
            fileEntry.Offset += fileStartPosition;
    }

    private static byte[] DecompressData(byte[] compressedData, int expectedLength)
    {
        using var compressedStream = new MemoryStream(compressedData);
        using var deflateStream = new DeflateStream(compressedStream, CompressionMode.Decompress);
        using var decompressedStream = new MemoryStream(expectedLength);

        deflateStream.CopyTo(decompressedStream);

        return decompressedStream.ToArray();
    }

    public class FileEntry(string name, int offset, int length, int compressedLength)
    {
        public string Name { get; } = name;
        public int Offset { get; internal set; } = offset;
        public int Length { get; } = length;
        public int CompressedLength { get; } = compressedLength;
    }
}