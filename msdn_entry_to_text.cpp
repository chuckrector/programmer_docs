#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>     // _setmode
#include <fcntl.h>

#define internal static
#define local_persist static
#define global_variable static

typedef unsigned long long u64;

typedef int b32;

typedef u64 umm;

#define Assert(Expression) if(!(Expression)) { *(int *)0 = 0; }
#define ArrayCount(Array) ((int)(sizeof(Array)/sizeof((Array)[0])))
#define ArrayCountZ(Array) (ArrayCount(Array)-1)

#define MEMORY_LIMIT (1024 * 1024 * 64)
global_variable char Memory[MEMORY_LIMIT];
global_variable umm MemoryUsed;
global_variable char TempBuffer[1024];

internal void *
PushSize(umm BytesNeeded)
{
    Assert((MemoryUsed + BytesNeeded) < MEMORY_LIMIT);
    void *Result = Memory + MemoryUsed;
    MemoryUsed += BytesNeeded;
    return(Result);
}
#define PushStruct(type) (type *)PushSize(sizeof(type))
#define PushArray(Count, type) (type *)PushSize(sizeof(type)*(Count))

#define HEADER_TITLE_KEY "title: "
#define HEADER_MINIMUM_SUPPORTED_CLIENT_KEY "req.target-min-winverclnt: "
#define HEADER_MINIMUM_SUPPORTED_SERVER_KEY "req.target-min-winversvr: "
#define HEADER_LIB_REQUIRED_KEY "req.lib: "
#define HEADER_DLL_REQUIRED_KEY "req.dll: "
#define HEADER_REQUIRED_HEADER_KEY "req.header: "
#define HEADER_REQUIRED_INCLUDE_HEADER_KEY "req.include-header: "

#define FOOTER_MINIMUM_SUPPORTED_CLIENT_KEY "| Minimum supported client | "
#define FOOTER_MINIMUM_SUPPORTED_SERVER_KEY "| Minimum supported server | "
#define FOOTER_LIB_REQUIRED_KEY "| Library | "
#define FOOTER_DLL_REQUIRED_KEY "| DLL | "
#define FOOTER_REQUIRED_HEADER_KEY "| Header | "

struct string
{
    int Length;
    char *StringData;
};

struct file_reader
{
    int At;
    string *FileData;
    string *Line;
    int PreviousLineAt;
};

struct param
{
    string *Name;
    string *Type;
    string *Description;
};

struct param_list
{
    int Count;
    param Params[50];
};

struct return_value
{
    string *Type;
    string *Description;
};

struct msdn_entry
{
    string *Title;
    string *Description;
    string *MinimumSupportedClient;
    string *MinimumSupportedServer;
    string *RequiredHeader;
    string *RequiredIncludeHeader; // NOTE(chuck): Optional
    string *RequiredLibrary;
    string *RequiredDLL;
    string *Syntax;
    string *Remarks;

    param_list Params;
    return_value ReturnValue;
};

internal b32
InBounds(int Value, int LowInclusive, int HighExclusive)
{
    b32 Result = (Value >= LowInclusive && Value < HighExclusive);
    return(Result);
}

internal char
PeekChar(file_reader *Reader, int Delta = 0)
{
    char Result = 0;

    int Offset = Reader->At + Delta;
    if(InBounds(Offset, 0, Reader->FileData->Length))
    {
        Result = Reader->FileData->StringData[Offset];
    }

    return(Result);
}

internal b32
IsNewLine(file_reader *Reader)
{
    int C0 = PeekChar(Reader);
    int C1 = PeekChar(Reader, 1);
    b32 Result = ((C0 == '\r') && (C1 == '\n')) ||
                  (C0 == '\r') ||
                  (C0 == '\n');
    return(Result);
}

internal b32
AtEnd(file_reader *Reader)
{
    b32 Result = (Reader->At >= Reader->FileData->Length);
    return(Result);
}

internal b32
StringLength(char *Chars)
{
    char *Start = Chars;
    while(*Chars) ++Chars;
    int Result = (Chars - Start);
    return(Result);
}

internal b32
IsOneOf(char C, char *Chars)
{
    b32 Result = 0;

    int CharsLength = StringLength(Chars);
    char *P = Chars;
    for(int Index = 0;
        Index < CharsLength;
        ++Index)
    {
        if(C == Chars[Index])
        {
            Result = 1;
            break;
        }
    }

    return(Result);
}

internal int
SkipNewLine(file_reader *Reader)
{
    int Result = 0;

    int C0 = PeekChar(Reader);
    int C1 = PeekChar(Reader, 1);
    if((C0 == '\r') && (C1 == '\n'))
    {
        Result = 2;
    }
    else if((C0 == '\r') || (C0 == '\n'))
    {
        Result = 1;
    }
    Reader->At += Result;
    return(Result);
}

internal int
SkipAnyAdjacent(file_reader *Reader, char *Chars)
{
    int Result = 0;

    while(!AtEnd(Reader))
    {
        if(IsOneOf(PeekChar(Reader), Chars))
        {
            ++Result;
        }
        else
        {
            break;
        }
    }

    return(Result);
}

internal string *
CutRight(string *String, int CutHere)
{
    string *Result = PushStruct(string);
    if (CutHere >= String->Length)
    {
        Result->Length = 0;
        Result->StringData = PushArray(1, char);
        Result->StringData[0] = 0;
    }
    else
    {
        Result->Length = (String->Length - CutHere);
        Result->StringData = String->StringData + CutHere;
    }

    return(Result);
}

// NOTE(chuck): This modifies the string in-place.  It collapses \[ and \] into [ and ] and appends a space for each.
internal string *
UnescapeBrackets(string *String)
{
    char *P = String->StringData;
    for(int Index = 0;
        Index < String->Length;
        ++Index, ++P)
    {
        if((P[0] == '\\') && ((P[1] == '[') || (P[1] == ']')))
        {
            for(int CollapseIndex = Index;
                CollapseIndex < String->Length - 1;
                ++CollapseIndex)
            {
                String->StringData[CollapseIndex] = String->StringData[CollapseIndex + 1];
            }
            String->StringData[--String->Length] = ' ';
        }
    }
    
    return(String);
}

internal string *
TrimRight(string *String, char *Chars)
{
    string *Result = PushStruct(string);
    Result->Length = String->Length;
    Result->StringData = String->StringData;

    int CharsLength = StringLength(Chars);
    char *P = String->StringData + String->Length - 1;
    int FoundCount = 0;
    while(P != String->StringData)
    {
        if(IsOneOf(*P, Chars))
        {
            ++FoundCount;
            --P;
        }
        else
        {
            break;
        }
    }
    Result->Length -= FoundCount;
    return(Result);
}

internal string *
TrimLeft(string *String, char *Chars)
{
    string *Result = PushStruct(string);
    Result->Length = String->Length;
    Result->StringData = String->StringData;

    int CharsLength = StringLength(Chars);
    int Index = 0;
    int FoundCount = 0;
    for(int Index = 0;
        Index < String->Length;
        ++Index)
    {
        if(IsOneOf(String->StringData[Index], Chars))
        {
            ++FoundCount;
        }
        else
        {
            break;
        }
    }
    Result->Length -= FoundCount;
    Result->StringData += FoundCount;
    return(Result);
}

internal b32
ReadLine(file_reader *Reader)
{
    b32 Result = 1;

    if(AtEnd(Reader))
    {
        Result = 0;
    }
    else
    {
        int LineStart = Reader->At;
        Reader->PreviousLineAt = LineStart;
        while(!AtEnd(Reader) && !IsNewLine(Reader))
        {
            ++Reader->At;
        }
        int LineLength = (Reader->At - LineStart);
        SkipNewLine(Reader);

        // NOTE(chuck): The reader Line is reused for every line.
        Reader->Line->Length = LineLength;
        Reader->Line->StringData = Reader->FileData->StringData + LineStart;
    }
    
    return(Result);
}

internal b32
StartsWith(string *String, string *Chars)
{
    b32 Result = 1;

    if(Chars->Length > String->Length)
    {
        Result = 0;
    }
    else
    {
        for(int Index = 0;
            Index < Chars->Length;
            ++Index)
        {
            if(String->StringData[Index] != Chars->StringData[Index])
            {
                Result = 0;
                break;
            }
        }
    }

    return(Result);
}

internal b32
StartsWith(string *String, char *Chars)
{
    b32 Result = 1;

    int CharsLength = StringLength(Chars);
    if(CharsLength > String->Length)
    {
        Result = 0;
    }
    else
    {
        for(int Index = 0;
            Index < CharsLength;
            ++Index)
        {
            if(String->StringData[Index] != Chars[Index])
            {
                Result = 0;
                break;
            }
        }
    }

    return(Result);
}

internal b32
StringsAreEqual(string *String, char *Chars)
{
    b32 Result = 1;

    int CharsLength = StringLength(Chars);
    if(String->Length != CharsLength)
    {
        Result = 0;
    }
    else
    {
        for(int Index = 0;
            Index < CharsLength;
            ++Index)
        {
            if(String->StringData[Index] != Chars[Index])
            {
                Result = 0;
                break;
            }
        }
    }

    return(Result);
}

internal void
ExpectStringsAreEqual(string *String, char *Chars)
{
    if(!StringsAreEqual(String, Chars))
    {
        fprintf(stderr, "An unexpected string was encountered.\n  Expected: %s\n  Received: %.*s\n", Chars, String->Length, String->StringData);
        exit(-1);
    }
}

internal void
PrintHeader(char Underline, char *Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    vsprintf(TempBuffer, Format, Args);
    va_end(Args);

    printf(TempBuffer);
    printf("\n");

    int L = StringLength(TempBuffer);
    for(int Index = 0;
        Index < L;
        ++Index)
    {
        printf("%c", Underline);
    }
    printf("\n");
}

internal string *
ToString(char *Chars)
{
    string *Result = PushStruct(string);
    Result->Length = StringLength(Chars);
    Result->StringData = Chars;
    return(Result);
}

internal void
Copy(char *Dest, char *Source, int Length)
{
    while(Length--) *Dest++ = *Source++;
}

internal string *
Prefix(string *String, string *Prefix)
{
    string *Result = PushStruct(string);
    Result->Length = Prefix->Length + String->Length;
    Result->StringData = PushArray(String->Length + Prefix->Length, char);
    Copy(Result->StringData, Prefix->StringData, Prefix->Length);
    Copy(Result->StringData + Prefix->Length, String->StringData, String->Length);
    return(Result);
}

internal string *
NewStringFrom(int Length, char *Chars)
{
    string *Result = PushStruct(string);
    Result->Length = Length;
    Result->StringData = Chars;
    return(Result);
}

internal void
SkipBlankLines(file_reader *Reader)
{
    while(!AtEnd(Reader) && IsNewLine(Reader))
    {
        ReadLine(Reader);
    }
}

internal string *
Substring(string *String, int StartInclusive, int EndExclusive)
{
    string *Result = PushStruct(string);
    Result->Length = EndExclusive - StartInclusive;
    Result->StringData = String->StringData + StartInclusive;
    return(Result);
}

internal b32
EndsWith(string *String, char *Chars)
{
    b32 Result = 1;

    int CharsLength = StringLength(Chars);
    if(CharsLength > String->Length)
    {
        Result = 0;
    }
    else
    {
        for(int Index = String->Length - CharsLength;
            Index < String->Length;
            ++Index)
        {
            if(String->StringData[Index] != *Chars++)
            {
                Result = 0;
                break;
            }
        }
    }

    return(Result);
}

internal string *
StripHtmlBold(string *String)
{
    if(StartsWith(String, "<b>") && EndsWith(String, "</b>"))
    {
        String = Substring(String, 3, String->Length - 4);
    }
    return(String);
}

int main(int ArgCount, char **Args)
{
    int Result = 0;

    if(ArgCount == 1)
    {
        printf("Usage: msdn_entry_to_text <GitHub .md file>\n");
        Result = 1;
    }
    else
    {
        _setmode(1, _O_BINARY);
        SetConsoleOutputCP(65001);

        char *MDFileName = Args[1];
        FILE *MDFile = fopen(MDFileName, "rb");
        if(MDFile)
        {
            int BytesRead = fread(Memory, 1, MEMORY_LIMIT, MDFile);
            fclose(MDFile);

            string Data = {BytesRead + 1, PushArray(BytesRead + 1, char)}; // NOTE(chuck): Null terminate so that newline checking can peek one ahead.
            file_reader Reader = {0, &Data, PushStruct(string)};

            msdn_entry Entry = {};

            ReadLine(&Reader);
            ExpectStringsAreEqual(Reader.Line, "---");

            while(ReadLine(&Reader) && !StringsAreEqual(Reader.Line, "---"))
            {
                if(StartsWith(Reader.Line, HEADER_TITLE_KEY))
                {
                    Entry.Title = CutRight(Reader.Line, ArrayCountZ(HEADER_TITLE_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_MINIMUM_SUPPORTED_CLIENT_KEY))
                {
                    Entry.MinimumSupportedClient = CutRight(Reader.Line, ArrayCountZ(HEADER_MINIMUM_SUPPORTED_CLIENT_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_MINIMUM_SUPPORTED_SERVER_KEY))
                {
                    Entry.MinimumSupportedServer = CutRight(Reader.Line, ArrayCountZ(HEADER_MINIMUM_SUPPORTED_SERVER_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_LIB_REQUIRED_KEY))
                {
                    Entry.RequiredLibrary = CutRight(Reader.Line, ArrayCountZ(HEADER_LIB_REQUIRED_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_DLL_REQUIRED_KEY))
                {
                    Entry.RequiredDLL = CutRight(Reader.Line, ArrayCountZ(HEADER_DLL_REQUIRED_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_REQUIRED_HEADER_KEY))
                {
                    Entry.RequiredHeader = CutRight(Reader.Line, ArrayCountZ(HEADER_REQUIRED_HEADER_KEY));
                }
                else if(StartsWith(Reader.Line, HEADER_REQUIRED_INCLUDE_HEADER_KEY))
                {
                     string *S = CutRight(Reader.Line, ArrayCountZ(HEADER_REQUIRED_INCLUDE_HEADER_KEY));
                     if (S->Length)
                     {
                        Entry.RequiredIncludeHeader = S;
                     }
                }
            }

            ExpectStringsAreEqual(Reader.Line, "---");

            string *MarkdownTitle = Prefix(Entry.Title, ToString("# "));
            while(ReadLine(&Reader))
            {
                if(StartsWith(Reader.Line, MarkdownTitle) || StartsWith(Reader.Line, "## -description"))
                {
                    ReadLine(&Reader);
                    int Start = Reader.At;
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "#"))
                    {
                        // NOTE(chuck): Do nothing.
                    }
                    Assert(StartsWith(Reader.Line, "#"));
                    Reader.At = Reader.PreviousLineAt;
                    string *S = NewStringFrom(Reader.At - Start, Reader.FileData->StringData + Start);
                    S = TrimRight(S, " \r\n");
                    Entry.Description = S;
                }
                else if(StartsWith(Reader.Line, "## -parameters"))
                {
                    ReadLine(&Reader);
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "## -returns"))
                    {
                        #define PARAM_KEY "### -param "
                        if(StartsWith(Reader.Line, PARAM_KEY))
                        {
                            param *Param = Entry.Params.Params + Entry.Params.Count++;
                            Param->Name = CutRight(Reader.Line, ArrayCountZ(PARAM_KEY));
                            SkipBlankLines(&Reader);

                            ReadLine(&Reader);
                            #define TYPE_KEY "Type: "
                            if(StartsWith(Reader.Line, TYPE_KEY))
                            {
                                string *S = CutRight(Reader.Line, ArrayCountZ(TYPE_KEY));
                                S = StripHtmlBold(S);
                                Param->Type = S;
                                SkipBlankLines(&Reader);
                            }
                            else
                            {
                                Reader.At = Reader.PreviousLineAt;
                            }

                            int Start = Reader.At;
                            while(ReadLine(&Reader) && !StartsWith(Reader.Line, "#"))
                            {
                                // NOTE(chuck): Do nothing.
                            }
                            Assert(StartsWith(Reader.Line, "#"));
                            Reader.At = Reader.PreviousLineAt;
                            string *S = NewStringFrom(Reader.At - Start, Reader.FileData->StringData + Start);
                            S = TrimRight(S, " \r\n");
                            Param->Description = S;
                        }
                    }
                    
                    Assert(StartsWith(Reader.Line, "## -returns"));
                    SkipBlankLines(&Reader);

                    ReadLine(&Reader);
                    if(StartsWith(Reader.Line, TYPE_KEY))
                    {
                        string *S = CutRight(Reader.Line, ArrayCountZ(TYPE_KEY));;
                        S = StripHtmlBold(S);
                        Entry.ReturnValue.Type = S;
                        SkipBlankLines(&Reader);
                    }
                    else
                    {
                        Reader.At = Reader.PreviousLineAt;
                    }

                    int Start = Reader.At;
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "#"))
                    {
                        // NOTE(chuck): Do nothing.
                    }
                    Assert(StartsWith(Reader.Line, "#"));
                    Reader.At = Reader.PreviousLineAt;
                    string *S = NewStringFrom(Reader.At - Start, Reader.FileData->StringData + Start);
                    S = TrimRight(S, " \r\n");
                    Entry.ReturnValue.Description = S;
                }
                else if(StartsWith(Reader.Line, "## Return value"))
                {
                    SkipBlankLines(&Reader);

                    ReadLine(&Reader);
                    if(StartsWith(Reader.Line, TYPE_KEY))
                    {
                        string *S = CutRight(Reader.Line, ArrayCountZ(TYPE_KEY));;
                        S = StripHtmlBold(S);
                        Entry.ReturnValue.Type = S;
                        SkipBlankLines(&Reader);
                    }
                    else
                    {
                        Reader.At = Reader.PreviousLineAt;
                    }

                    int Start = Reader.At;
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "#"))
                    {
                        // NOTE(chuck): Do nothing.
                    }
                    Assert(StartsWith(Reader.Line, "#"));
                    Reader.At = Reader.PreviousLineAt;
                    string *S = NewStringFrom(Reader.At - Start, Reader.FileData->StringData + Start);
                    S = TrimRight(S, " \r\n");
                    Entry.ReturnValue.Description = S;
                }
                else if(StartsWith(Reader.Line, "## Remarks") || StartsWith(Reader.Line, "## -remarks"))
                {
                    SkipBlankLines(&Reader);
                    int Start = Reader.At;
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "##"))
                    {
                        // NOTE(chuck): Do nothing.
                    }
                    Assert(StartsWith(Reader.Line, "##"));
                    Reader.At = Reader.PreviousLineAt;
                    string *S = NewStringFrom(Reader.At - Start, Reader.FileData->StringData + Start);
                    S = TrimRight(S, " \r\n");
                    Entry.Remarks = S;
                }
                else if(StartsWith(Reader.Line, "## Requirements"))
                {
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "##"))
                    {
                        if(StartsWith(Reader.Line, FOOTER_MINIMUM_SUPPORTED_CLIENT_KEY))
                        {
                            Assert(!Entry.MinimumSupportedClient);

                            string *S = TrimRight(Reader.Line, " |");
                            S = CutRight(S, ArrayCountZ(FOOTER_MINIMUM_SUPPORTED_CLIENT_KEY));
                            S = UnescapeBrackets(S);
                            Entry.MinimumSupportedClient = S;
                        }
                        else if(StartsWith(Reader.Line, FOOTER_MINIMUM_SUPPORTED_SERVER_KEY))
                        {
                            Assert(!Entry.MinimumSupportedServer);

                            string *S = TrimRight(Reader.Line, " |");
                            S = CutRight(S, ArrayCountZ(FOOTER_MINIMUM_SUPPORTED_SERVER_KEY));
                            S = UnescapeBrackets(S);
                            Entry.MinimumSupportedServer = S;
                        }
                        else if(StartsWith(Reader.Line, FOOTER_LIB_REQUIRED_KEY))
                        {
                            Assert(!Entry.RequiredLibrary);

                            string *S = TrimRight(Reader.Line, " |");
                            Entry.RequiredLibrary = CutRight(S, ArrayCountZ(FOOTER_LIB_REQUIRED_KEY));
                        }
                        else if(StartsWith(Reader.Line, FOOTER_DLL_REQUIRED_KEY))
                        {
                            Assert(!Entry.RequiredDLL);

                            string *S = TrimRight(Reader.Line, " |");
                            Entry.RequiredDLL = CutRight(S, ArrayCountZ(FOOTER_DLL_REQUIRED_KEY));
                        }
                        else if(StartsWith(Reader.Line, FOOTER_REQUIRED_HEADER_KEY))
                        {
                            Assert(!Entry.RequiredHeader);

                            string *S = TrimRight(Reader.Line, " |");
                            Entry.RequiredHeader = CutRight(S, ArrayCountZ(FOOTER_REQUIRED_HEADER_KEY));
                        }
                    }
                }
                else if(StartsWith(Reader.Line, "## Syntax"))
                {
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "```"))
                    {
                        // NOTE(chuck): Do nothing.
                    }
                    Assert(StartsWith(Reader.Line, "```"));

                    int Start = Reader.At;
                    int LastStart = Start;
                    while(ReadLine(&Reader) && !StartsWith(Reader.Line, "```"))
                    {
                        LastStart = Reader.At;
                    }
                    Assert(StartsWith(Reader.Line, "```"));
                    Reader.At = LastStart;

                    Entry.Syntax = PushStruct(string);
                    Entry.Syntax->Length = (Reader.At - Start);
                    Entry.Syntax->StringData = Reader.FileData->StringData + Start;
                    Entry.Syntax = TrimRight(Entry.Syntax, "\r\n");
                }
            }

            PrintHeader('=', "%.*s", Entry.Title->Length, Entry.Title->StringData);
            printf("Minimum supported client: %.*s\n", Entry.MinimumSupportedClient->Length, Entry.MinimumSupportedClient->StringData);
            printf("Minimum supported server: %.*s\n\n", Entry.MinimumSupportedServer->Length, Entry.MinimumSupportedServer->StringData);
            printf(" Header: %.*s", Entry.RequiredHeader->Length, Entry.RequiredHeader->StringData);
            if(Entry.RequiredIncludeHeader)
            {
                printf(" (include %.*s)", Entry.RequiredIncludeHeader->Length, Entry.RequiredIncludeHeader->StringData);
            }
            printf("\n");
            printf("Library: %.*s\n", Entry.RequiredLibrary->Length, Entry.RequiredLibrary->StringData);
            printf("    DLL: %.*s\n\n", Entry.RequiredDLL->Length, Entry.RequiredDLL->StringData);

            if(Entry.Syntax)
            {
                PrintHeader('-', "Syntax");
                printf("%.*s\n\n", Entry.Syntax->Length, Entry.Syntax->StringData);
            }

            if(Entry.Description)
            {
                PrintHeader('-', "Description");
                printf("%.*s\n\n", Entry.Description->Length, Entry.Description->StringData);
            }

            if(Entry.Params.Count)
            {
                PrintHeader('-', "Parameters");
                for(int Index = 0;
                    Index < Entry.Params.Count;
                    ++Index)
                {
                    param *Param = Entry.Params.Params + Index;
                    if(Param->Type)
                    {
                        printf("%.*s ", Param->Type->Length, Param->Type->StringData);
                    }
                    printf("%.*s\n", Param->Name->Length, Param->Name->StringData);
                    printf("    %.*s\n\n", Param->Description->Length, Param->Description->StringData);
                }
            }

            PrintHeader('-', "Return value");
            if(Entry.ReturnValue.Type)
            {
                printf("Type: %.*s\n", Entry.ReturnValue.Type->Length, Entry.ReturnValue.Type->StringData);
            }
            if(Entry.ReturnValue.Description)
            {
                printf("%.*s\n", Entry.ReturnValue.Description->Length, Entry.ReturnValue.Description->StringData);
            }
            printf("\n");

            if(Entry.Remarks)
            {
                PrintHeader('-', "Remarks");
                printf("%.*s\n", Entry.Remarks->Length, Entry.Remarks->StringData);
            }
        }
        else
        {
            fprintf(stderr, "The file could not be opened.\n");
            Result = 1;
        }
    }

    return(Result);
}
