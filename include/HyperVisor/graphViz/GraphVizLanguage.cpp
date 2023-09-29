#include "GraphVizLanguage.hpp"
#include <ntddk.h>


/*
CharBuffer GraphVizLanguage::EntryPointOfGraphVizLanguage(_In_ PCH _NameOfGraph, _Inout_ CharBuffer* WriteTo)
{
    NameOfGraph = _NameOfGraph;

    STRCAT(WriteTo->ValuesCWI, DigraphQuote);
    STRCAT(WriteTo->ValuesCWI, NameOfGraph);
    STRCAT(WriteTo->ValuesCWI, StartOfdigraph);

	//return (strlen(DigraphQuote) + strlen(NameOfGraph) + strlen(StartOfdigraph));
    CharBuffer objCharBuffer;
    RtlCopyMemory(&objCharBuffer, WriteTo, sizeof(*WriteTo));

    return objCharBuffer;
}

CharBuffer GraphVizLanguage::EndOfFile(_In_ CharBuffer* WriteTo)
{ 
    STRCAT(WriteTo->ValuesCWI, EndOfdigraph); 
    //return strlen(EndOfdigraph); 

    return WriteTo;
}

CharBuffer* GraphVizLanguage::AddGraph(_In_ CharBuffer* WriteTo, _In_ PCH From, _In_ PCH To)
{
    STRCAT(WriteTo->ValuesCWI, Address);
    STRCAT(WriteTo->ValuesCWI, From);

    STRCAT(WriteTo->ValuesCWI, Line);

    STRCAT(WriteTo->ValuesCWI, Address);
    STRCAT(WriteTo->ValuesCWI, To);

    //return (strlen(From) + strlen(Line) + strlen(To));
    return WriteTo;
}

CharBuffer* GraphVizLanguage::SpecificNodeLabel(_In_ CharBuffer* WriteTo, _In_ PCH _LabelText)
{
    STRCAT(WriteTo->ValuesCWI, StartOfLabel);
    STRCAT(WriteTo->ValuesCWI, Label);
    STRCAT(WriteTo->ValuesCWI, _LabelText);
    STRCAT(WriteTo->ValuesCWI, EndOfLabel);
    STRCAT(WriteTo->ValuesCWI, "\n");

    //return (strlen(StartOfLabel) + strlen(Label) + strlen(_LabelText) + strlen(EndOfLabel) + strlen("\n"));
    return WriteTo;
}

CharBuffer* GraphVizLanguage::NodeRecordShapeAttributeOfDigraph(_In_ CharBuffer* WriteTo)
{
    STRCAT(WriteTo->ValuesCWI, Node);
    STRCAT(WriteTo->ValuesCWI, StartOfLabel);
    STRCAT(WriteTo->ValuesCWI, Shape);
    STRCAT(WriteTo->ValuesCWI, RecordShape);
    STRCAT(WriteTo->ValuesCWI, EndOfLabel);

    //return (strlen(Node) + strlen(StartOfLabel) + strlen(Shape) + strlen(RecordShape) + strlen(EndOfLabel));
    return WriteTo;
}
*/