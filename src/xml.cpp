#include "xml.h"

#include <stdexcept>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

namespace lastpass
{

struct Xml::PrivateData
{
    PrivateData():
        document(nullptr)
    {
    }

    xmlDocPtr document;
};

Xml::Xml(std::string const &text): d(new PrivateData)
{
    d->document = xmlReadMemory(text.c_str(), text.size(), "", nullptr, 0);
    if (d->document == nullptr)
        throw std::runtime_error("Failed to parse XML");
}

Xml::~Xml()
{
    xmlFreeDoc(d->document);
}

std::string Xml::get_attribute(std::string const &xpath) const
{
    std::unique_ptr<xmlXPathContext, decltype(&xmlXPathFreeContext)>context(
        xmlXPathNewContext(d->document),
        &xmlXPathFreeContext);
    if (context.get() == nullptr)
        return "";

    std::unique_ptr<xmlXPathObject, decltype(&xmlXPathFreeObject)>result(
        xmlXPathEvalExpression(reinterpret_cast<xmlChar const *>(xpath.c_str()), context.get()),
        &xmlXPathFreeObject);
    if (result.get() == nullptr)
        return "";

    xmlNodeSet const *nodes = result->nodesetval;
    if (nodes == nullptr ||
        nodes->nodeNr <= 0 ||
        nodes->nodeTab[0]->type != XML_ATTRIBUTE_NODE)
        return "";

    return reinterpret_cast<char const *>(((xmlAttrPtr)nodes->nodeTab[0])->children->content);
}

}
