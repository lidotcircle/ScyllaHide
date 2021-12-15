#include "process/mem_indexable.h"


#define GET_VAL(type) { \
        if (this->flush_on_get_value) \
            this->flush(); \
        union { \
            type f; \
            char c[sizeof(type)]; \
        } val; \
        for (size_t i=0;i<sizeof(type);i++) \
            val.c[i] = this->get_at(index+i); \
        return val.f; \
    }

#define SET_VAL(type, val) { \
        this->flush(); \
        union { \
            type f; \
            char c[sizeof(type)]; \
        } v; \
        v.f = val; \
        for (size_t i=0;i<sizeof(type);i++) \
            this->set_at(index+i, v.c[i]); \
        this->flush(); \
    }


MemIndexable::MemIndexable(): flush_on_get_value(false) {}

void MemIndexable::set_flush_before_get_value(bool value) {
    this->flush_on_get_value = value;
}

void MemIndexable::flush() {
}

uint8_t MemIndexable::get_u8(addr_t index) {
    GET_VAL(uint8_t);
}
void MemIndexable::set_u8(addr_t index, uint8_t value) {
    SET_VAL(uint8_t, value);
}
uint16_t MemIndexable::get_u16(addr_t index) {
    GET_VAL(uint16_t);
}
void MemIndexable::set_u16(addr_t index, uint16_t value) {
    SET_VAL(uint16_t, value);
}
uint32_t MemIndexable::get_u32(addr_t index) {
    GET_VAL(uint32_t);
}
void MemIndexable::set_u32(addr_t index, uint32_t value) {
    SET_VAL(uint32_t, value);
}
uint64_t MemIndexable::get_u64(addr_t index) {
    GET_VAL(uint64_t);
}
void MemIndexable::set_u64(addr_t index, uint64_t value) {
    SET_VAL(uint64_t, value);
}

float MemIndexable::get_float(addr_t index) {
    GET_VAL(float);
}
void MemIndexable::set_float(addr_t index, float value) {
    SET_VAL(float, value);
}
double MemIndexable::get_double(addr_t index) {
    GET_VAL(double);
}
void MemIndexable::set_double(addr_t index, double value) {
    SET_VAL(double, value);
}
