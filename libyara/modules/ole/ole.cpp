extern "C"
{
#include <yara/modules.h>
}
#include "pole/pole.h"

#define MODULE_NAME ole

extern "C" 
begin_declarations
  declare_integer("is_encrypted");
  declare_integer("auto_open");
  declare_integer("auto_close");
end_declarations

extern "C" int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

extern "C" int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

enum class OLEXLSRecordId : uint16_t
{
  Eof = 0x000A,
  Label = 0x0018,
  FilePass = 0x002F,
  BoundSheet = 0x0085,
  Dconn = 0x0876,
  Supbook = 0x01AE,
  Formula = 6
};

struct OLEXLSRecordHeader
{
  OLEXLSRecordId type;  // opcode
  uint16_t size;
};

enum class BuiltinNames
{
  Invalid = 0,
  AutoOpen = 1,
  AutoClose = 2,
  Autoactivate = 0xA,
  Autodeactivate = 0xB
};

class OLERecordIterator
{
 public:
  OLERecordIterator(const uint8_t* data) : m_data(data) {}

  const OLEXLSRecordHeader* operator*()
  {
    return reinterpret_cast<const OLEXLSRecordHeader*>(m_data);
  }

  OLERecordIterator& operator++()
  {
    m_data += sizeof(OLEXLSRecordHeader) + this->operator*()->size;
    return *this;
  }

  bool operator!=(const OLERecordIterator& other)
  {
    return other.m_data != m_data;
  }

 private:
  const uint8_t* m_data;
};

// FIXME: this code allows you to read past the buffer's end.
class OLEFile
{
 public:
  OLEFile(const uint8_t* data, size_t size)
      : m_data(data), m_size(size)
  {
  }

  OLERecordIterator begin() const { return OLERecordIterator(m_data); }
  OLERecordIterator end() const { return OLERecordIterator(m_data + m_size); }

 private:
  const uint8_t* m_data;
  size_t m_size;
};

void parseLabelHeader(
    const OLEXLSRecordHeader* record,
    bool& found_auto_open,
    bool& found_auto_close)
{
  if (record->size < 16)
  {
    return;
  }

  const char* record_data = reinterpret_cast<const char*>(record + 1);
  if (record_data[0] & 0x20)
  {
    BuiltinNames name = (BuiltinNames)record_data[15];
    if (name == BuiltinNames::AutoOpen)
    {
      found_auto_close = true;
    }
    else if (name == BuiltinNames::AutoClose)
    {
      found_auto_close = true;
    }
    return;
  }

  // FIXME: implement:
  //getBuiltInNameByStr(readUserDefinedName(record_data));
}

void extractOleFields(
    const uint8_t* data,
    size_t size,
    bool& found_auto_open,
    bool& found_auto_close,
    bool& is_encrypted)
{
  for (const OLEXLSRecordHeader* record : OLEFile(data, size))
  {
    if (record->type == OLEXLSRecordId::FilePass)
    {
      is_encrypted = true;
      return;
    }
    else if (record->type == OLEXLSRecordId::Label)
    {
      parseLabelHeader(record, found_auto_open, found_auto_close);
      return;
    }
  }
}

extern "C" int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
    // Scanner should provide an extra boolean parameter "is_ole_file'
  if (module_data_size != 1 ||
      *static_cast<bool*>(module_data) != true)
  {
    return ERROR_SUCCESS;
  }

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  const uint8_t* block_data = block->fetch_data(block);

  bool found_auto_open = false;
  bool found_auto_close = false;
  bool is_encrypted = false;
  extractOleFields(
      block_data, block->size, found_auto_open, found_auto_close, is_encrypted);

  set_integer(static_cast<int>(is_encrypted), module_object, "is_encrypted");
  set_integer(static_cast<int>(found_auto_open), module_object, "auto_open");
  set_integer(static_cast<int>(found_auto_close), module_object, "auto_close");
  return ERROR_SUCCESS;
}

extern "C" int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
