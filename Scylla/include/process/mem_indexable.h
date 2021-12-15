#ifndef _MEM_INDEXABLE_H_
#define _MEM_INDEXABLE_H_

#include <stdlib.h>
#include <stdint.h>


class MemIndexable
{
private:
    // flush before getting u8 u16 .. float double
    bool flush_on_get_value;

public:
    using addr_t = size_t;
    MemIndexable();

    virtual ~MemIndexable() = default;
    virtual char get_at(addr_t index) const = 0;
    virtual void set_at(addr_t index, char value) = 0;

    virtual uint8_t  get_u8 (addr_t index);
    virtual void     set_u8 (addr_t index, uint8_t value);
    virtual uint16_t get_u16(addr_t index);
    virtual void     set_u16(addr_t index, uint16_t value);
    virtual uint32_t get_u32(addr_t index);
    virtual void     set_u32(addr_t index, uint32_t value);
    virtual uint64_t get_u64(addr_t index);
    virtual void     set_u64(addr_t index, uint64_t value);

    virtual float   get_float(addr_t index);
    virtual void    set_float(addr_t index, float value);
    virtual double  get_double(addr_t index);
    virtual void    set_double(addr_t index, double value);

    void set_flush_before_get_value(bool value);
    virtual void flush();
};

#endif // _MEM_INDEXABLE_H_
