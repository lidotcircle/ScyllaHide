#pragma once

#include <ntdll/ntdll.h>
#include "smalloc-new-delete.h"

#define DLLExport __declspec(dllexport)
#define DLLExport_C extern "C" __declspec(dllexport)
