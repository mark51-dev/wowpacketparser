#include <windows.h>
#include <iostream>


typedef void(__thiscall* sendPacket)(int* pThis, int* a1, int* a2);
sendPacket sendFunc = (sendPacket)0x00632B50;

void printPacket(DWORD packetType, DWORD lengthh)
{
    switch (packetType)
    {
    case 0xBB:
        printf("[SEND] - [MSG_MOVE_JUMP] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x95:
        printf("[SEND] - [CMSG_MESSAGECHAT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x12E:
        printf("[SEND] - [CMSG_CAST_SPELL] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x12F:
        printf("[SEND] - [CMSG_CANCEL_CAST] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x13D:
        printf("[SEND] - [CMSG_SET_SELECTION] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x3D0:
        printf("[SEND] - [CMSG_TARGET_CAST] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x010:
        printf("[SEND] - [CMSG_LEARN_SPELL] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x391:
        printf("[SEND] - [CMSG_TIME_SYNC_RESP] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0DA:
        printf("[SEND] - [MSG_MOVE_SET_FACING] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x3D3:
        printf("[SEND] - [CMSG_SET_ACTIVE_VOICE_CHANNEL] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0B5:
        printf("[SEND] - [MSG_MOVE_START_FORWARD] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0B7:
        printf("[SEND] - [MSG_MOVE_STOP] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0BA:
        printf("[SEND] - [MSG_MOVE_STOP_STRAFE] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0B8:
        printf("[SEND] - [MSG_MOVE_START_STRAFE_LEFT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0B9:
        printf("[SEND] - [MSG_MOVE_START_STRAFE_LEFT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0EE:
        printf("[SEND] - [MSG_MOVE_HEARTBEAT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0C9:
        printf("[SEND] - [MSG_MOVE_FALL_LAND] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0BD:
        printf("[SEND] - [MSG_MOVE_START_TURN_RIGHT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0BC:
        printf("[SEND] - [MSG_MOVE_START_TURN_LEFT] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0BE:
        printf("[SEND] - [MSG_MOVE_STOP_TURN] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    case 0x0B6:
        printf("[SEND] - [MSG_MOVE_START_BACKWARD] - %X | Packet Length %d \n", packetType, lengthh);
        break;
    default:
        printf("[SEND] - UNKNOWN - %X | Packet Length %d \n", packetType, lengthh);
        break;
    }
}



char* jumpBack;

void packetHandler(byte* packet, DWORD lengthh) {

    void* dest[256];
    memcpy(dest, packet, lengthh);
    printPacket(*(DWORD*)dest, lengthh);
    
    /*for (DWORD i = 0; i < lengthh; i++)
    {
        printf("%02X ", ((byte*)dest)[i]);
    }
    printf("\n");*/
}

__declspec(naked) void ourFunc() {
    DWORD packetLength;
    byte* uncryptedPacket;
    

    __asm {
        pushad
        pushfd

        mov edx, dword ptr [ebp + 0x8]
        mov edx, [edx + 0x10]
        mov packetLength, edx

        mov edx, dword ptr[ebp + 0x8]
        mov edx, dword ptr[edx + 0x4]
        mov uncryptedPacket, edx

        popfd
        popad
    }

    packetHandler(uncryptedPacket, packetLength);
    

    __asm jmp[jumpBack]
}





bool Detour32(void* src, void* dst, int len)
{
    if (len < 5) return false;

    DWORD curProtection;
    VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);

    memset(src, 0x90, len);

    uintptr_t relativeAddress = ((uintptr_t)dst - (uintptr_t)src) - 5;

    *(BYTE*)src = 0xE9;
    *(uintptr_t*)((uintptr_t)src + 1) = relativeAddress;

    DWORD temp;
    VirtualProtect(src, len, curProtection, &temp);

    return true;
}

char* TrampHook32(char* src, char* dst, const intptr_t len)
{
    // Make sure the length is greater than 5
    if (len < 5) return 0;

    // Create the gateway (len + 5 for the overwritten bytes + the jmp)
    void* gateway = VirtualAlloc(0, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //Write the stolen bytes into the gateway
    memcpy(gateway, src, len);

    // Get the gateway to destination addy
    intptr_t  gatewayRelativeAddr = ((intptr_t)src - (intptr_t)gateway) - 5;

    // Add the jmp opcode to the end of the gateway
    *(char*)((intptr_t)gateway + len) = 0xE9;

    // Add the address to the jmp
    *(intptr_t*)((intptr_t)gateway + len + 1) = gatewayRelativeAddr;

    // Perform the detour
    Detour32(src, dst, len);

    return (char*)gateway;
}


// 0046772E | E8 5DFAFFFF              | call <wow.sub_467190>                                     |
//0x0046720B

//006B0B60

DWORD WINAPI Menue(HINSTANCE hModule)
{
    

    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    jumpBack = TrampHook32((char*)0x006B0B53, (char*)ourFunc, 6);
    printf("hehe");
    while (true) {
        if (GetAsyncKeyState(VK_NUMPAD7) & 0x1) {
            printf("hehe\n");
            sendFunc((int*)0x11EB0940, (int*)0x0432FBC0, (int*)0x0432FBF0);
        }
        Sleep(200);
    }
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Menue, NULL, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}