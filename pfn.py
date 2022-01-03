# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Creator: Aviel Zohar (memoryforensicsanalysis@gmail.com)

import sys
import time
import struct
import threading, functools
import urllib.request, urllib.parse, urllib.error
from typing import Callable, List, Generator, Iterable
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import info
from volatility3.plugins.windows import vadinfo
from volatility3.framework.configuration import requirements
from volatility3.framework import renderers, interfaces, objects, exceptions, symbols, constants
import tkinter as tk
from tkinter import N, E, W, S, END, YES, BOTH, PanedWindow, Tk, VERTICAL, LEFT, Menu, StringVar, RIGHT, SOLID
import tkinter.messagebox as messagebox
import tkinter.colorchooser
from tkinter.ttk import Frame, Treeview, Scrollbar, Combobox
import tkinter.font
import os, re
import time
import io
import logging
vollog = logging.getLogger(__name__)

try:
    import csv
    has_csv = True
except ImportError:
    has_csv = False

try:
    from ttkthemes import ThemedStyle
    has_themes = True
except ImportError:
    has_themes = False

app = None
TreeTable_CULUMNS = {} # an TreeTable global to store all the user preference for the header selected.
file_path = ''
ABS_X = 60
ABS_Y = 60
file_slice = 8 if sys.platform == 'win32' else 5
right_click_event = '<Button-2>' if sys.platform == 'darwin' else '<Button-3>'

PAGES_LIST = {0: 'Zeroed',
                1: 'Free',
                2: 'Standby',
                3: 'Modified',
                4: 'ModifiedNoWrite',
                5: 'Bad',
                6: 'Active',
                7: 'Transition'}

POOL_TAGS = {
  "AzWp": " HDAudio.sys  - HD Audio Class Driver (AzWaveport, HdaWaveRTminiport)\r\n",
  "SCLb": " <unknown>    -  Smart card driver library\r\n",
  "Wmit": " <unknown>    - Wmi Trace\r\n",
  "Wmis": " <unknown>    - Wmi SysId allocations\r\n",
  "Wmiq": " <unknown>    - Wmi NBQ Blocks\r\n",
  "smWd": " nt!store or rdyboost.sys - ReadyBoost store contents rundown work item\r\n",
  "PsJa": " nt!ps        - Job access control state\r\n",
  "Gtvp": " win32k!PFFOBJ::bAddPvtData           - GDITAG_PFF_DATA\r\n",
  "FMts": " fltmgr.sys   -       Tree Stack\r\n",
  "FMtr": " fltmgr.sys   -       Temporary Registry information\r\n",
  "Dfsm": " win32k.sys                           - GDITAG_ENG_EVENT\r\n",
  "FMtp": " fltmgr.sys   -       Non Paged TxVol context structures\r\n",
  "IpAT": " ipsec.sys    -  AH headers in transport mode\r\n",
  "IpAU": " ipsec.sys    -  AH headers in tunnel mode\r\n",
  "AzWd": " HDAudio.sys  - HD Audio Class Driver (AzWidget)\r\n",
  "HpMM": " pnpmem.sys   - HotPlug Memory Driver\r\n",
  "W32l": " win32k!W32PIDLOCK::vInit             - GDITAG_W32PIDLOCK\r\n",
  "Qp??": " <unknown>    - Generic Packet Classifier (MSGPC)\r\n",
  "Wmim": " <unknown>    - Wmi KM to UM Notification Buffers\r\n",
  "IpAX": " ipsec.sys    -  key acquire contexts\r\n",
  "FMtb": " fltmgr.sys   -       TXN_PARAMETER_BLOCK structure\r\n",
  "Ppcs": " pacer.sys    - PACER Pipe Counter Sets\r\n",
  "Ppcr": " nt!pnp       - plug-and-play critical allocations\r\n",
  "Usai": " win32k!zzzAttachThreadInput          - USERTAG_ATTACHINFO\r\n",
  "SmMt": " mrxsmb10.sys    -      SMB1   mailslot buffer  (special build only)\r\n",
  "SmMs": " mrxsmb.sys    - SMB miscellaneous\r\n",
  "WmiR": " <unknown>    - Wmi Registration info blocks\r\n",
  "PXg": " ndproxy.sys - PX_CMAF_TAG\r\n",
  "RaUE": " storport.sys - RaidUnitAllocateResources\r\n",
  "Usac": " win32k!_CreateAcceleratorTable       - USERTAG_ACCEL\r\n",
  "Gpft": " win32k!pAllocateAndInitializePFT     - GDITAG_PFT\r\n",
  "Gful": " win32k.sys                           - GDITAG_FULLSCREEN\r\n",
  "SrWI": " sr.sys       -         Work queue item\r\n",
  "WmiG": " <unknown>    - Allocation of WMIGUID\r\n",
  "SmVr": " mrxsmb10.sys    -      SMB1   VNetroot  (special build only)\r\n",
  "DCdm": " win32kbase!DirectComposition::CRemotingRenderTargetMarshaler::_allocate                  - DCOMPOSITIONTAG_REMOTINGRENDERTARGETMARSHALER\r\n",
  "WmiD": " <unknown>    - Wmi Registration DataSouce\r\n",
  "WmiC": " <unknown>    - Wmi Create Pump Thread Work Item\r\n",
  "DCdj": " win32kbase!DirectComposition::CSharedWriteDcompTargetMarshaler::_allocate                - DCOMPOSITIONTAG_SHAREDWRITEDCOMPTARGETMARSHALER\r\n",
  "SmMa": " mrxsmb10.sys    -      SMB1   mid atlas  (special build only)\r\n",
  "Ppcd": " nt!pnp       - PnP critical device database\r\n",
  "DCdg": " win32kbase!DirectComposition::CSharedWriteDesktopTargetMarshaler::_allocate              - DCOMPOSITIONTAG_SHAREDWRITEDESKTOPTARGETMARSHALER\r\n",
  "Gpff": " win32k.sys                           - GDITAG_PFF\r\n",
  "SmMm": " mrxsmb.sys   -         SMB mm allocated structures.\r\n",
  "MupI": " mup.sys      - Windows Server 2003 and prior versions: DFS Irp Context allocation\r\n",
  "DCdc": " win32kbase!DirectComposition::CDwmChannel::_allocate                                     - DCOMPOSITIONTAG_DWMCHANNEL\r\n",
  "DCdb": " win32kbase!DirectComposition::CDCompDynamicArrayBase::_allocate                          - DCOMPOSITIONTAG_DYNAMICARRAYBASE\r\n",
  "Obeb": " nt!ob        - object tables extra bit tables via EX handle.c\r\n",
  "UlVH": " http.sys     - Virtual Host\r\n",
  "Dfs ": " <unknown>    - Distributed File System\r\n",
  "DpPl": " FsDepends.sys - FsDepends Parent Link Block\r\n",
  "DErz": " devolume.sys - Drive extender write super blocks request: DEVolume!DEDiskSet::WriteSuperBlocksRequest\r\n",
  "DEry": " devolume.sys - Drive extender start or create request: DEVolume!DiskSetVolume::StartOrCreateRequest\r\n",
  "DErx": " devolume.sys - Drive extender shutdown system request: DEVolume!DiskSetVolume::ShutdownRequest\r\n",
  "DErw": " devolume.sys - Drive extender read write target: DEVolume!ReadWriteTarget\r\n",
  "DErv": " devolume.sys - Drive extender repair volume request: DEVolume!DiskSetVolume::RepairVolumeDamageRequest\r\n",
  "DEru": " devolume.sys - Drive extender shutdown request: DEVolume!DEDiskSet::ShutdownRequest\r\n",
  "DErt": " devolume.sys - Drive extender start request: DEVolume!DEDiskSet::StartRequest\r\n",
  "DErs": " devolume.sys - Drive extender delete or shutdown request: DEVolume!DiskSetVolume::DeleteOrShutdownRequest\r\n",
  "DErr": " devolume.sys - Drive extender read request: DEVolume!ReadRequest\r\n",
  "DErp": " devolume.sys - Drive extender replicator: DEVolume!Replicator\r\n",
  "DEro": " devolume.sys - Drive extender become out of date request: DEVolume!VolumeChunk::BecomeOutOfDateRequest\r\n",
  "DErn": " devolume.sys - Drive extender new epoch request: DEVolume!DEDiskSet::NewEpochRequest\r\n",
  "DErm": " devolume.sys - Drive extender range lock manager: DEVolume!RangeLockManager\r\n",
  "DErl": " devolume.sys - Drive extender long and notify request: DEVolume!DiskSetVolume::LogAndNotifyRequest\r\n",
  "DCav": " win32kbase!DirectComposition::CSharedWriteAnimationTriggerMarshaler::_allocate           - DCOMPOSITIONTAG_SHAREDWRITEANIMATIONTRIGGERMARSHALER\r\n",
  "DErh": " devolume.sys - Drive extender replicate chunk: DEVolume!ReplicateChunk\r\n",
  "DErg": " devolume.sys - Drive extender registry: DEVolume!DERegistry\r\n",
  "DEre": " devolume.sys - Drive extender decommit all request: DEVolume!DiskSetVolume::DecommitAllRequest\r\n",
  "Cdma": " cdfs.sys     - CDFS Mcb array\r\n",
  "DErc": " devolume.sys - Drive extender commit request: DEVolume!VolumeChunk::CommitRequest\r\n",
  "Ddk ": " <unknown>    - Default for driver allocated memory (user's of ntddk.h)\r\n",
  "DEra": " devolume.sys - Drive extender disk event request\r\n",
  "DCza": " win32kbase!DirectComposition::CSharedClientProjectedShadowCasterMarshaler::_allocate     - DCOMPOSITIONTAG_CLIENTPROJECTEDSHADOWCASTERMARSHALER\r\n",
  "DCzc": " win32kbase!DirectComposition::CProjectedShadowCasterMarshaler::_allocate                 - DCOMPOSITIONTAG_PROJECTEDSHADOWCASTERMARSHALER\r\n",
  "DCzb": " win32kbase!DirectComposition::CSharedHostProjectedShadowCasterMarshaler::_allocate       - DCOMPOSITIONTAG_HOSTPROJECTEDSHADOWCASTERMARSHALER\r\n",
  "Fl6D": " tcpip.sys    - FL6t DataLink Addresses\r\n",
  "FMtn": " fltmgr.sys   -       Temporary file names\r\n",
  "smEd": " nt!store     -         ReadyBoost virtual store manager key descriptor allocation for logging\r\n",
  "UHCD": " <unknown>    - Universal Host Controller (USB - Intel Controller)\r\n",
  "DCzr": " win32kbase!DirectComposition::CProjectedShadowReceiverMarshaler::_allocate               - DCOMPOSITIONTAG_PROJECTEDSHADOWRECEIVERMARSHALER\r\n",
  "DCdi": " win32kbase!DirectComposition::CSharedReadDcompTargetMarshaler::_allocate                 - DCOMPOSITIONTAG_SHAREDREADDCOMPTARGETMARSHALER\r\n",
  "Usdm": " win32k!CreateDCompositionHwndTargetInfo - USERTAG_DCOMPHWNDTARGETINFO\r\n",
  "Umen": " win32kbase!HMAllocObject - USERTAG_MENU\r\n",
  "FIvp": " fileinfo.sys - FileInfo FS-filter Volume Properties\r\n",
  "Via4": " dxgmms2.sys  - GPU scheduler context state\r\n",
  "Via5": " dxgmms2.sys  - GPU scheduler queue packet\r\n",
  "Via6": " dxgmms2.sys  - GPU scheduler DMA packet\r\n",
  "Via7": " dxgmms2.sys  - GPU scheduler VSync cookie\r\n",
  "ScVk": " <unknown>    -      read buffer for DVD keys\r\n",
  "Via1": " dxgmms2.sys  - GPU scheduler node state\r\n",
  "Via2": " dxgmms2.sys  - GPU scheduler process state\r\n",
  "Via3": " dxgmms2.sys  - GPU scheduler device state\r\n",
  "ObSq": " nt!ob        - object security descriptors (query)\r\n",
  "ViSh": " dxgkrnl.sys  - Video scheduler\r\n",
  "VMhd": " vmbushid.sys    - Virtual Machine Input VSC Driver\r\n",
  "Via8": " dxgmms2.sys  - GPU scheduler GPU sync object\r\n",
  "Via9": " dxgmms2.sys  - GPU scheduler present info\r\n",
  "FIvn": " fileinfo.sys - FileInfo FS-filter Volume Name\r\n",
  "Dmga": " <unknown>    - mga (matrox) video driver\r\n",
  "Giog": " win32k.sys                           - GDITAG_COMPOSEDGAMMA\r\n",
  "Gbaf": " win32k.sys                           - GDITAG_BRUSH_FREELIST\r\n",
  "Wmij": " <unknown>    - Wmi GuidMaps\r\n",
  "NbL0": " netbt.sys    - NetBT lower connection\r\n",
  "VsSw": " vmswitch.sys - Virtual Machine Network Switch Driver\r\n",
  "Wmii": " <unknown>    - Wmi InstId chunks\r\n",
  "NbL1": " netbt.sys    - NetBT lower connection\r\n",
  "MmBk": " nt!mm        - Mm banked sections\r\n",
  "CcAs": " nt!cc        - Cache Manager Async cached read structure\r\n",
  "DCjc": " win32kbase!DirectComposition::CColorBrushMarshaler::_allocate                            - DCOMPOSITIONTAG_COLORBRUSHMARSHALER\r\n",
  "Viad": " dxgmms2.sys  - GPU scheduler hardware queue\r\n",
  "Viae": " dxgmms2.sys  - GPU scheduler monitored fence\r\n",
  "Viaf": " dxgmms2.sys  - GPU scheduler sync point\r\n",
  "NbL3": " netbt.sys    - NetBT lower connection\r\n",
  "Viaa": " dxgmms2.sys  - GPU scheduler history buffer\r\n",
  "Viab": " dxgmms2.sys  - GPU scheduler periodic frame notification state\r\n",
  "Rqrv": " <unknown>    - Registry query buffer\r\n",
  "UlIC": " http.sys     - Irp Context\r\n",
  "Ucmp": " http.sys     - Multipart String Buffer\r\n",
  "Gdwd": " win32k.sys                           - GDITAG_WATCHDOG\r\n",
  "WlDt": " writelog.sys - Writelog drain target\r\n",
  "StEl": " storport.sys - PortpErrorInitRecords storport!_STORAGE_TRACE_CONTEXT_INTERNAL.ErrorLogRecords\r\n",
  "RxNf": " rdbss.sys - RDBSS non paged FCB\r\n",
  "SWre": " <unknown>    -         relations\r\n",
  "FwfD": " mpsdrv.sys   - MPSDRV driver buffer for flattening NET_BUFFFER\r\n",
  "Txgd": " ntfs.sys     - TxfData global structure\r\n",
  "FCuu": " dxgkrnl!CEndpointResourceStateManager::PrepareIncrementalUpdateForUser - FLIPCONTENT_INCREMENTALRESOURCEUPDATEFORUSER\r\n",
  "WPCT": " BasicRender.sys - Basic Render DX Context\r\n",
  "AlHa": " nt!alpc      - ALPC port handle table\r\n",
  "Usal": " win32k!InitSwitchWndInfo             - USERTAG_ALTTAB\r\n",
  "Uspo": " win32k!QueuePowerRequest             - USERTAG_POWER\r\n",
  "FCub": " dxgkrnl!CEndpointResourceStateManager::PrepareIncrementalUpdateForStateManager - FLIPCONTENT_INCREMENTALRESOURCEUPDATEFORCONSUMER\r\n",
  "DDsr": " win32kbase!DirectComposition::CDataSourceReaderMarshaler::_allocate                      - DCOMPOSITIONTAG_DATASOURCEREADERMARSHALER\r\n",
  "Xtra": " <unknown>    - EXIFS Extra Create\r\n",
  "PmDD": " partmgr.sys  - Partition Manager device descriptor\r\n",
  "VmLb": " volmgrx.sys  - Log blocks\r\n",
  "D2d ": " <unknown>    - Device Object to DosName rtns (ntos\\rtl\\dev2dos.c)\r\n",
  "Qphf": " <unknown>    -      HandleFactory\r\n",
  "RxMs": " rdbss.sys - RDBSS miscellaneous\r\n",
  "VHDI": " vhdmp.sys    - VHD IO Range pool\r\n",
  "RxMx": " rdbss.sys - RDBSS mini-rdr\r\n",
  "VHDA": " vhdmp.sys    - VHD generic allocator pool\r\n",
  "AtC ": " <unknown>    - IDE disk configuration\r\n",
  "RaAM": " storport.sys - RaidAllocateAddressMapping storport!_MAPPED_ADDRESS\r\n",
  "VHDS": " vhdmp.sys    - VHD symbolic link\r\n",
  "Gubm": " win32k.sys                           - GDITAG_UMODE_BITMAP\r\n",
  "NBF ": " <unknown>    - general NBF allocations\r\n",
  "SYPK": " syspart.lib  - Kernel mode system partition detection allocations\r\n",
  "FVE?": " fvevol.sys   - Full Volume Encryption Filter Driver (Bitlocker Drive Encryption)\r\n",
  "DCdo": " win32kbase!DirectComposition::CSharedWriteRemotingRenderTargetMarshaler::_allocate       - DCOMPOSITIONTAG_SHAREDWRITEREMOTINGRENDERTARGETMARSHALER\r\n",
  "VHDh": " vhdmp.sys    - VHD header\r\n",
  "VHDi": " vhdmp.sys    - VHD IO Range\r\n",
  "VHDn": " vhdmp.sys    - VHD filename\r\n",
  "SmTh": " mrxsmb.sys    - SMB thunk\r\n",
  "VHDl": " vhdmp.sys    - VHD LUN\r\n",
  "VHDm": " vhdmp.sys    - VHD bitmap\r\n",
  "VHDb": " vhdmp.sys    - VHD Block Allocation Table\r\n",
  "HcDr": " hcaport.sys - HCAPORT_TAG_DEVICE_RELATIONS\r\n",
  "VHDa": " vhdmp.sys    - VHD generic allocator\r\n",
  "VHDf": " vhdmp.sys    - VHD file entry\r\n",
  "PNDP": " <unknown>    - Power Abort Dpc Routine\r\n",
  "Gmap": " win32k!InitializeFontSignatures      - GDITAG_FONT_MAPPER\r\n",
  "flnk": " <unknown>    - font link tag used in ntgdi\\gre\r\n",
  "call": " <unknown>    - debugging call tables\r\n",
  "NMhf": " netio.sys    - Handle Factory pool\r\n",
  "RxCv": " mrxsmb.sys - RXCE VcEndpoint\r\n",
  "VHDr": " vhdmp.sys    - VHD read buffer\r\n",
  "VHDs": " vhdmp.sys    - VHD sector map\r\n",
  "VHDp": " vhdmp.sys    - VHD filepath\r\n",
  "Dnod": " <unknown>    - Device node structure\r\n",
  "Ukdp": " win32k!Win32UserInitialize           - USERTAG_KERNELDISPLAYINFO\r\n",
  "VHDw": " vhdmp.sys    - VHD work item\r\n",
  "VHDt": " vhdmp.sys    - VHD tracking information\r\n",
  "RxM1": " rdbss.sys - RDBSS VNetRoot name\r\n",
  "fboX": " <unknown>    - EXIFS FOBXVF List\r\n",
  "RxM3": " rdbss.sys - RDBSS querypath name\r\n",
  "RxM2": " rdbss.sys - RDBSS canonical name\r\n",
  "RxM5": " rdbss.sys - RDBSS reparse buffer name\r\n",
  "RxM4": " rdbss.sys - RDBSS treeconnect name\r\n",
  "MmPh": " nt!mm        - Physical memory nodes for querying memory ranges\r\n",
  "PmRL": " partmgr.sys  - Partition Manager remove lock\r\n",
  "FSun": " nt!fsrtl     - File System Run Time\r\n",
  "MmPg": " nt!mm        - Mm page table pages at init time\r\n",
  "MmPd": " nt!mm        - Mm page table commitment bitmaps\r\n",
  "NBFu": " <unknown>    - NBF UI frame\r\n",
  "MmPb": " nt!mm        - Paging file bitmaps\r\n",
  "NBFs": " <unknown>    - NBF provider stats\r\n",
  "NBFp": " <unknown>    - NBF packet\r\n",
  "MmPa": " nt!mm        - pagefile space deletion slist entries\r\n",
  "NBFn": " <unknown>    - NBF netbios name\r\n",
  "CMpa": " nt!cm        - registry post apcs\r\n",
  "CMpb": " nt!cm        - registry post blocks\r\n",
  "CMpe": " nt!cm        - registry post events\r\n",
  "NBFi": " <unknown>    - NBF tdi connection info\r\n",
  "NBFf": " <unknown>    - NBF address file object\r\n",
  "NBFg": " <unknown>    - NBF registry path name\r\n",
  "NBFd": " <unknown>    - NBF packet pool descriptor\r\n",
  "NBFe": " <unknown>    - NBF bind & export names\r\n",
  "NBFb": " <unknown>    - NBF receive buffer\r\n",
  "NBFc": " <unknown>    - NBF connection object\r\n",
  "Cvli": " <unknown>    - EXIFS Cached Volume Info\r\n",
  "NBFa": " <unknown>    - NBF address object\r\n",
  "WmiL": " <unknown>    - WmiLIb\r\n",
  "Adbe": " win32k.sys                           - GDITAG_ATM_FONT\r\n",
  "FVEx": " fvevol.sys   - Read/write control structures\r\n",
  "FVEw": " fvevol.sys   - Worker threads\r\n",
  "FVEv": " fvevol.sys   - Conversion allocations\r\n",
  "FVEr": " fvevol.sys   - Reserved mapping addresses\r\n",
  "FVEp": " fvevol.sys   - Write buffers\r\n",
  "PsCr": " nt!ps        - Working set change record (temporary allocation)\r\n",
  "FVEl": " fvevol.sys   - FVELIB allocations\r\n",
  "VHD?": " vhdmp.sys    - VHD allocation\r\n",
  "V2??": " vhdmp.sys    - VHD2 pool allocation\r\n",
  "FVEc": " fvevol.sys   - Cryptographic allocations\r\n",
  "LS09": " srvnet.sys   -     SRVNET LookasideList level 9 allocation 128K Bytes\r\n",
  "LS08": " srvnet.sys   -     SRVNET LookasideList level 8 allocation 64K Bytes\r\n",
  "IPmf": " <unknown>    - Free memory (only in checked builds)\r\n",
  "IPmg": " <unknown>    - Group\r\n",
  "LS03": " srvnet.sys   -     SRVNET LookasideList level 3 allocation 2K Bytes\r\n",
  "LS02": " srvnet.sys   -     SRVNET LookasideList level 2 allocation 1K Bytes\r\n",
  "LS01": " srvnet.sys   -     SRVNET LookasideList level 1 allocation 512 Bytes\r\n",
  "LS00": " srvnet.sys   -     SRVNET LookasideList level 0 allocation 256 Bytes\r\n",
  "LS07": " srvnet.sys   -     SRVNET LookasideList level 7 allocation 32K Bytes\r\n",
  "LS06": " srvnet.sys   -     SRVNET LookasideList level 6 allocation 16K Bytes\r\n",
  "LS05": " srvnet.sys   -     SRVNET LookasideList level 5 allocation 8K Bytes\r\n",
  "IPmo": " <unknown>    - Outgoing Interface\r\n",
  "IPms": " <unknown>    - Source\r\n",
  "DCpc": " win32kbase!DirectComposition::CPrimitveColorMarshaler::_allocate                         - DCOMPOSITIONTAG_PRIMITIVECOLORMARSHALER\r\n",
  "p2hw": " perm2dll.dll - Permedia2 display driver - hwinit.c\r\n",
  "smEK": " nt!store     -         ReadyBoost encryption key\r\n",
  "Vi22": " dxgmms2.sys  - Video memory manager DMA buffer\r\n",
  "TWTa": " tcpip.sys    - Echo Request Timer Table\r\n",
  "UsI3": " win32k!NSInstrumentation::CBackTraceStoreEx::Create   - USERTAG_BACKTRACE_STORE\r\n",
  "IoDn": " nt!io        - Io device name info\r\n",
  "RxCd": " mrxsmb.sys - RXCE TDI\r\n",
  "Gh?8": " win32k.sys                           - GDITAG_HMGR_PAL_TYPE\r\n",
  "Gh?9": " win32k.sys                           - GDITAG_HMGR_ICMLCS_TYPE\r\n",
  "Gh?:": " win32k.sys                           - GDITAG_HMGR_LFONT_TYPE\r\n",
  "Gh?;": " win32k.sys                           - GDITAG_HMGR_RFONT_TYPE\r\n",
  "I4ba": " tcpip.sys    - IPv4 Local Broadcast Addresses\r\n",
  "RxCc": " mrxsmb.sys - RXCE connection\r\n",
  "Gh?6": " win32k.sys                           - GDITAG_HMGR_CLIENTOBJ_TYPE\r\n",
  "Gh?7": " win32k.sys                           - GDITAG_HMGR_PATH_TYPE\r\n",
  "RSFS": " <unknown>    -      Recall Queue\r\n",
  "Gh?1": " win32k.sys                           - GDITAG_HMGR_DC_TYPE\r\n",
  "I4bf": " tcpip.sys    - IPv4 Generic Buffers (Source Address List allocations)\r\n",
  "RSFO": " <unknown>    -      File Obj queue\r\n",
  "RSFN": " <unknown>    -      File Name\r\n",
  "UsI0": " win32k!NSInstrumentation::CBackTraceStorageUnit::Create   - USERTAG_BACKTRACE_STORAGE_UNIT\r\n",
  "Atom": " <unknown>    - Atom Tables\r\n",
  "TmRm": " nt!tm        - Tm KRESOURCEMANAGER object\r\n",
  "I6rd": " tcpip.sys    - IPv6 Receive Datagrams Arguments\r\n",
  "ppPT": " pvhdparser.sys - Proxy Virtual Machine Storage VHD Parser Driver (parser)\r\n",
  "SmDg": " mrxsmb.sys    - SMB datagram endpoint\r\n",
  "DEfg": " devolume.sys - Drive extender filter: DEVolume!DEFilter\r\n",
  "MSfa": " refs.sys     - Minstore filtered AVL\r\n",
  "Lr!!": " <unknown>    -     Cancel request context blocks\r\n",
  "Gh?L": " win32k.sys                           - GDITAG_HMGR_DRVOBJ_TYPE\r\n",
  "SDe ": " smbdirect.sys - SMB Direct large receive buffers\r\n",
  "Gh?E": " win32k.sys                           - GDITAG_HMGR_META_TYPE\r\n",
  "SmDc": " mrxsmb10.sys    -      SMB1   dir query buffer (special build only)\r\n",
  "Gh?@": " win32k.sys                           - GDITAG_HMGR_BRUSH_TYPE\r\n",
  "Gh?A": " win32k.sys                           - GDITAG_HMGR_UMPD_TYPE\r\n",
  "TuSB": " tunnel.sys   - Tunnel stack block\r\n",
  "IPm?": " <unknown>    - IP Multicasting\r\n",
  "PsCa": " nt!ps        - APC queued at thread create time.\r\n",
  "Ushr": " win32k!AllocateAndLinkHidPageOnlyRequest - USERTAG_HIDPAGEREQUEST\r\n",
  "Pcdb": " <unknown>    - Pcmcia bus enumerator, Databook controller specific structures\r\n",
  "PSE3": " pse36.sys    - Physical Size Extension driver\r\n",
  "LSep": " srv.sys      -     SMB1 endpoint\r\n",
  "PnPb": " nt!pnp       - PnP BIOS resource manipulation\r\n",
  "Nbtw": " netbt.sys    - NetBT device linkage names\r\n",
  "WfpM": " netio.sys    - WFP filter match buffers\r\n",
  "WfpL": " netio.sys    - WFP fast cache\r\n",
  "TmRq": " nt!tm        - Tm Propagation Request\r\n",
  "Idqf": " tcpip.sys    - IPsec DoS Protection QoS flow\r\n",
  "NDdp": " ndis.sys     - NDIS_TAG_DBG_P\r\n",
  "Txvc": " ntfs.sys     - TXF_VCB\r\n",
  "WfpE": " netio.sys    - WFP extension\r\n",
  "VHur": " vmusbhub.sys - Virtual Machine USB Hub Driver (URB)\r\n",
  "Txvf": " ntfs.sys     - TXF_VSCB_FILE_SIZES\r\n",
  "FMea": " fltmgr.sys   -       EA buffer for create\r\n",
  "Txvd": " ntfs.sys     - TXF_VSCB_TO_DEREF\r\n",
  "LSlr": " srv.sys      -     SMB1 BlockTypeLargeReadX\r\n",
  "TunP": " <unknown>    - Tunnel cache oddsized pool-allocated elements\r\n",
  "LpcZ": " <unknown>    - LPC Zone\r\n",
  "RS??": " <unknown>    - Remote Storage\r\n",
  "DEqm": " devolume.sys - Drive extender queued message: DEVolume!QueuedMessage\r\n",
  "WfpS": " netio.sys    - WFP startup\r\n",
  "WfpR": " netio.sys    - WFP RPC\r\n",
  "SeFS": " nt!se        - Security File System Notify Context\r\n",
  "HidC": " hidclass.sys - HID Class driver\r\n",
  "DErd": " devolume.sys - Drive extender decommit request: DEVolume!VolumeChunk::DecommitRequest\r\n",
  "PFXM": " nt!PoFx      - Runtime Power Management Framework\r\n",
  "NtF?": " ntfs.sys     -     Unknown NTFS source module\r\n",
  "DCpf": " win32kbase!DirectComposition::CSharedWritePrimitiveColorMarshaler::_allocate             - DCOMPOSITIONTAG_SHAREDWRITEPRIMITIVECOLORMARSHALER\r\n",
  "DErb": " devolume.sys - Drive extender become dirty request: DEVolume!VolumeChunk::BecomeDirtyRequest\r\n",
  "HidP": " hidparse.sys - HID Parser\r\n",
  "Wl2l": " wfplwfs.sys  - WFP L2 LWF context\r\n",
  "Tdx ": " tdx.sys      - TDX Generic Buffers (Address, Entity information, Interface change allocations)\r\n",
  "Ppre": " nt!pnp       - resource allocation and translation\r\n",
  "smFp": " nt!store     -         ReadyBoost virtual forward progress entry\r\n",
  "NtFR": " ntfs.sys     -     RestrSup.c\r\n",
  "Pprl": " nt!pnp       - routines to manipulate relations list\r\n",
  "DEcl": " devolume.sys - Drive extender delayed cleaner: DEVolume!DelayedCleaner\r\n",
  "Uspy": " win32k!CreateProp                    - USERTAG_PROPLIST\r\n",
  "DCxp": " win32kbase!DirectComposition::CCrossChannelParentVisualMarshaler::_allocate              - DCOMPOSITIONTAG_CROSSCHANNELPARENTVISUALMARSHALER\r\n",
  "TdxP": " tdx.sys      - TDX Transport Layer Providers\r\n",
  "FbCx": " tcpip.sys    - Inet feature fallback contexts\r\n",
  "TdxR": " tdx.sys      - TDX Received Data\r\n",
  "Uspp": " win32k!AllocateAndLinkHidTLCInfo     - USERTAG_PNP\r\n",
  "Uspq": " win32k!CreatePointerDeviceInfo       - USERTAG_PARALLELPROP\r\n",
  "Uspr": " win32k!GetPrivateProfileStruct       - USERTAG_PROFILE\r\n",
  "Usps": " win32k!InitPlaySound                 - USERTAG_PLAYSOUND\r\n",
  "Uspt": " win32k!AllocThreadPointerData        - USERTAG_POINTERTHREADDATA\r\n",
  "Uspv": " win32k!ContactVisualization          - USERTAG_POINTERVISUALIZATION\r\n",
  "Uspw": " win32k!CDynamicArray::Add            - USERTAG_DYNAMICARRAY\r\n",
  "Grgb": " win32k.sys                           - GDITAG_PALETTE_RGB_XLATE\r\n",
  "Wl2g": " wfplwfs.sys  - WFP L2 generic block\r\n",
  "ScsP": " <unknown>    - non-pnp SCSI port.c\r\n",
  "Setp": " <unknown>    - SETUPDD SpMemAlloc calls\r\n",
  "TdxA": " tdx.sys      - TDX Transport Addresses\r\n",
  "TdxB": " tdx.sys      - TDX Transport Layer Buffers\r\n",
  "FSrn": " nt!fsrtl     - File System Run Time\r\n",
  "DEct": " devolume.sys - Drive extender chunk table\r\n",
  "TdxM": " tdx.sys      - TDX Message Indication Buffers\r\n",
  "RpcM": " msrpc.sys    - all msrpc.sys allocations not covered elsewhere\r\n",
  "Dcdd": " cdd.dll      - Canonical display driver\r\n",
  "Grgn": " win32k.sys                           - GDITAG_REGION\r\n",
  "MmWe": " nt!mm        - Work entries for writing out modified filesystem pages.\r\n",
  "Uspf": " win32k!CommitHoldingFrame            - USERTAG_POINTERINPUTFRAME\r\n",
  "Uspg": " win32k!GeneratePointerMessage        - USERTAG_POINTERINPUTMSG\r\n",
  "LBea": " <unknown>    -     Ea buffer\r\n",
  "MSpa": " refs.sys     - Minstore hash table entries (incl. and primarily SmsPage)\r\n",
  "ScB?": " classpnp.sys - ClassPnP misc allocations\r\n",
  "ST* ": " <unknown>    - New MMC compliant storage drivers\r\n",
  "Rpcs": " msrpc.sys    - Memory shared b/n MSRpc and caller\r\n",
  "Rpcr": " msrpc.sys    - MSRpc resources\r\n",
  "Wl2c": " wfplwfs.sys  - WFP L2 classify cache\r\n",
  "PSwt": " nt!po        - Power switch structure\r\n",
  "VsRD": " vmswitch.sys - Virtual Machine Network Switch Driver (RNDIS device)\r\n",
  "LBel": " <unknown>    -     Election context\r\n",
  "Dfb ": " <unknown>    - framebuf video driver\r\n",
  "UlQT": " http.sys     - TCI Tracker\r\n",
  "Txrm": " ntfs.sys     - TXF_RMCB\r\n",
  "Tdxc": " tdx.sys      - TDX Control Channels\r\n",
  "Gh?4": " win32k.sys                           - GDITAG_HMGR_RGN_TYPE\r\n",
  "PfVA": " nt!pf        - Pf VA prefetching buffers\r\n",
  "Rpcm": " msrpc.sys    - MSRpc memory allocations\r\n",
  "Rpcl": " msrpc.sys    - MSRpc memory logging - checked build only\r\n",
  "Uskf": " win32k!LoadKeyboardLayoutFile        - USERTAG_KBDFILE\r\n",
  "sidg": " <unknown>    - GDI spooler events\r\n",
  "AdSv": " vmsrvc.sys   - Virtual Machines Additions Service\r\n",
  "CctX": " <unknown>    - EXIFX FCB Commit CTX\r\n",
  "UlQW": " http.sys     - TCI WMI\r\n",
  "VHif": " vmusbhub.sys - Virtual Machine USB Hub Driver (interface)\r\n",
  "ScDS": " <unknown>    -      srb allocation\r\n",
  "ScDP": " <unknown>    -      read capacity buffer\r\n",
  "SmXc": " mrxsmb.sys    - SMB exchange\r\n",
  "StDa": " netio.sys    - WFP stream inspection data\r\n",
  "ScDW": " <unknown>    -      work-item context\r\n",
  "ScDU": " <unknown>    -      update capacity path\r\n",
  "ScDI": " <unknown>    -      sense info buffers\r\n",
  "ScDN": " <unknown>    -      disk name code\r\n",
  "ScDM": " <unknown>    -      mbr checksum code\r\n",
  "ScDC": " <unknown>    -      disable cache paths\r\n",
  "ScDA": " <unknown>    -      Info Exceptions\r\n",
  "Type": " <unknown>    - Type objects\r\n",
  "ScDG": " <unknown>    -      disk geometry buffer\r\n",
  "Flng": " tcpip.sys    - Framing Layer Generic Buffers (Tunnel/Port change notifications, ACLs)\r\n",
  "SePh": " nt!se        - Dummy image page hash structure, used when CI is disabled\r\n",
  "UshP": " win32k!HidCreateDeviceInfo           - USERTAG_HIDPREPARSED\r\n",
  "PoSL": " <unknown>    - Power shutdown event list\r\n",
  "Gini": " <unknown>    -     Gdi fast mutex\r\n",
  "ScDs": " <unknown>    -      start device paths\r\n",
  "ScDp": " <unknown>    -      disk partition lists\r\n",
  "VsOb": " vmswitch.sys - Virtual Machine Network Switch Driver (object allocation)\r\n",
  "FLln": " <unknown>    - shared lock tree node\r\n",
  "ScPm": " <unknown>    -      address mapping lists\r\n",
  "SrHK": " sr.sys       -         Hash key\r\n",
  "SrHH": " sr.sys       -         Hash header\r\n",
  "RRlm": " <unknown>    - RTL_RANGE_LIST_MISC_TAG\r\n",
  "ScDc": " <unknown>    -      disk allocated completion c\r\n",
  "SePr": " nt!se        - Security Privilege Set\r\n",
  "ScDa": " <unknown>    -      SMART\r\n",
  "ScDg": " <unknown>    -      update disk geometry paths\r\n",
  "NwFw": " <unknown>    - ntos\\tdi\\fwd\r\n",
  "smPb": " rdyboost.sys -         ReadyBoost persist log buffer\r\n",
  "smPc": " rdyboost.sys -         ReadyBoost persist log context\r\n",
  "UsbS": " usbser.sys   - USB Serial Driver\r\n",
  "SCl0": " <unknown>    -  Litronic 220\r\n",
  "FTrc": " <unknown>    - Fault tolerance Slist tag.\r\n",
  "smPi": " rdyboost.sys -         ReadyBoot population ranges index\r\n",
  "ScPi": " <unknown>    -      Sense Info\r\n",
  "Ppdd": " nt!pnp       - new Plug-And-Play driver entries and IRPs\r\n",
  "Ppde": " nt!pnp       - routines to perform device removal\r\n",
  "smPr": " rdyboost.sys -         ReadyBoot population ranges\r\n",
  "FMwi": " fltmgr.sys   -       Work item structures\r\n",
  "Qpct": " <unknown>    -      Client blocks\r\n",
  "SeLu": " nt!se        - Security LUID and Attributes array\r\n",
  "NfR?": " nfsrdr.sys   - NFS (Network File System) client re-director\r\n",
  "UlQF": " http.sys     - TCI Filter\r\n",
  "ScVS": " <unknown>    -      buffer for reads of DVD on-disk structures\r\n",
  "SmNr": " mrxsmb10.sys    -      SMB1   NetRoot  (special build only)\r\n",
  "UlQG": " http.sys     - TCI Generic\r\n",
  "Usbr": " win32k!NtUserShutdownBlockReasonCreate - USERTAG_BLOCKREASON\r\n",
  "ScD?": " <unknown>    -   Disk\r\n",
  "PfDq": " nt!pf        - Pf Directory query buffers\r\n",
  "Ifs ": " <unknown>    - Default file system allocations (user's of ntifs.h)\r\n",
  "DCgs": " win32kbase!DirectComposition::CColorGradientStopMarshaler::_allocate                     - DCOMPOSITIONTAG_COLORGRADIENTSTOPMARSHALER\r\n",
  "RefD": " refs.sys     -     DEALLOCATED_RECORDS\r\n",
  "VsCT": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney TCP context)\r\n",
  "VdPN": " dxgkrnl.sys  - Video display mode management\r\n",
  "DmpS": " dumpsvc.sys  - Crashdump Service Driver\r\n",
  "ScPc": " <unknown>    -      Fake common buffer\r\n",
  "Fecf": " netio.sys    - WFP filter engine callout context\r\n",
  "Usbg": " win32k!xxxLogClipData                - USERTAG_DEBUG\r\n",
  "DCgi": " win32kbase!DirectComposition::CGenericInkMarshaler::_allocate                            - DCOMPOSITIONTAG_GENERICINKMARSHALER\r\n",
  "Fecc": " netio.sys    - WFP filter engine classify context\r\n",
  "TcFC": " tcpip.sys    - TCP Fastopen Cookies\r\n",
  "PmPE": " partmgr.sys  - Partition Manager partition entry\r\n",
  "ScD ": " <unknown>    -      generic tag\r\n",
  "SeLs": " nt!se        - Security Logon Session\r\n",
  "smBt": " nt!store or rdyboost.sys - ReadyBoost various B+Tree allocations\r\n",
  "DCge": " win32kbase!DirectComposition::CGaussianBlurEffectMarshaler::_allocate                    - DCOMPOSITIONTAG_GAUSSIANBLUREFFECTMARSHALER\r\n",
  "TCPC": " <unknown>    - TCP connection pool\r\n",
  "AzJd": " HDAudio.sys  - HD Audio Class Driver (JackDetector)\r\n",
  "NDoc": " ndis.sys     - NDIS_TAG_OPEN_CONTEXT\r\n",
  "NDob": " ndis.sys     - open block\r\n",
  "NDoa": " ndis.sys     - NDIS_TAG_OID_ARRAY\r\n",
  "NDof": " ndis.sys     - NDIS_TAG_OFFLOAD\r\n",
  "ScLA": " classpnp.sys -      allocation to check for autorun disable\r\n",
  "TcIn": " tcpip.sys    - TCP Inputs\r\n",
  "APIC": " pnpapic.sys  - I/O APIC Driver\r\n",
  "Gfnt": " win32k!RFONTOBJ::bRealizeFont        - GDITAG_RFONT\r\n",
  "MmWS": " nt!mm        - Working set swap support\r\n",
  "NDop": " ndis.sys     - NDIS_TAG_PM_PROT_OFFLOAD\r\n",
  "FOCX": " nt!fsrtl     - File System Run Time File Object Context structure\r\n",
  "LANE": " atmlane.sys  - LAN Emulation Client for ATM\r\n",
  "MmNo": " nt!mm        - Inernal physical memory nodes\r\n",
  "Usrt": " win32k!xxxDrawMenuItemText           - USERTAG_RTL\r\n",
  "Lric": " <unknown>    -     Instance Control Blocks\r\n",
  "Qpcf": " <unknown>    -      ClassificationFamily\r\n",
  "WlIb": " writelog.sys - Writelog I/O buffer\r\n",
  "TCPr": " <unknown>    - TCP request pool\r\n",
  "Ioin": " <unknown>    - Io interrupts\r\n",
  "PcSx": " <unknown>    - WDM audio stuff\r\n",
  "EQPn": " tcpip.sys    - EQoS policy net entry\r\n",
  "TMce": " dxgkrnl!CCompositionFrame::TokenTableEntry::Allocate  - TOKENMANAGER_TOKENTABLEENTRY\r\n",
  "Wmiw": " <unknown>    - Wmi Notification Waiting Buffers, in paged queue waiting for IOCTL\r\n",
  "MmCS": " nt!mm        - Pagefile CRC verification buffer\r\n",
  "UcSP": " http.sys     - Process Server Information\r\n",
  "InCS": " tcpip.sys    - Inet Compartment Set\r\n",
  "UcST": " http.sys     - Server info table\r\n",
  "DCvr": " win32kbase!DirectComposition::CVisualCaptureMarshaler::_allocate                         - DCOMPOSITIONTAG_VISUALCAPTUREMARSHALER\r\n",
  "TTsp": " tcpip.sys    - TCP TCB Sends\r\n",
  "Psjb": " nt!ps        - Job set array (temporary allocation)\r\n",
  "Gwnd": " win32k.sys                           - GDITAG_WNDOBJ\r\n",
  "PsTp": " nt!ps        - Thread termination port block\r\n",
  "Strm": " <unknown>    - Streams and streams transports allocations\r\n",
  "PcCr": " <unknown>    - WDM audio stuff\r\n",
  "Ggdv": " win32k.sys                           - GDITAG_GDEVICE\r\n",
  "Strg": " <unknown>    - Dynamic Translated strings\r\n",
  "UcSN": " http.sys     - Server name\r\n",
  "LLDP": " mslldp.sys   - LLDP protocol driver allocations\r\n",
  "MmCr": " nt!mm        - Mm fork clone roots\r\n",
  "MmCp": " nt!mm        - Colored page counts for physical memory allocations\r\n",
  "UdpA": " tcpip.sys    - UDP Endpoints\r\n",
  "MmCt": " nt!mm        - Mm debug tracing\r\n",
  "VWFF": " vwififlt.sys - Virtual Wi-Fi Filter Driver (object allocation)\r\n",
  "VsRm": " vmswitch.sys - Virtual Machine Network Switch Driver (routing)\r\n",
  "MmCx": " nt!mm        - info for dynamic section extension\r\n",
  "VWFB": " vwifibus.sys - Virtual Wi-Fi Bus Driver\r\n",
  "idle": " <unknown>    - Power Manager idle handler\r\n",
  "VsSW": " vmswitch.sys - Virtual Machine Network Switch Driver (WDF)\r\n",
  "VraP": " <unknown>    - parallel class driver\r\n",
  "MmCd": " nt!mm        - Mm fork clone descriptors\r\n",
  "Via0": " dxgmms2.sys  - GPU scheduler adapter state\r\n",
  "MmCi": " nt!mm        - Mm control areas for images\r\n",
  "MmCh": " nt!mm        - Mm fork clone headers\r\n",
  "MmCm": " nt!mm        - Calls made to MmAllocateContiguousMemory\r\n",
  "InCo": " tcpip.sys    - Inet Compartment\r\n",
  "DChx": " win32kbase!DirectComposition::CHolographicViewer::_allocate                              - DCOMPOSITIONTAG_HOLOGRAPHICVIEWERMARSHALER\r\n",
  "LSpm": " srv.sys      -     SMB1 paged MFCB\r\n",
  "I4s6": " tcpip.sys    - IPsec SADB v6\r\n",
  "Gapl": " win32k.sys                           - GDITAG_APAL_TABLE\r\n",
  "Ubws": " win32kmin!xxxMinSendPointerMessageWorker   - USERTAG_BASE_WINDOW_SENTLIST\r\n",
  "MuSi": " mup.sys      - Surrogate info\r\n",
  "LSpc": " srv.sys      -     SMB1 paged connection\r\n",
  "CrtH": " <unknown>    - EXIFS Create Header\r\n",
  "Uspx": " win32k!GetCustomFlickPath            - USERTAG_PTRCFG\r\n",
  "TcHT": " tcpip.sys    - TCP Hash Tables\r\n",
  "LSdc": " srv.sys      -     SMB1 BlockTypeDirCache\r\n",
  "LSdb": " srv.sys      -     SMB1 data buffer\r\n",
  "UlLL": " http.sys     - Log File Buffer\r\n",
  "Gxlt": " win32k.sys                           - GDITAG_PXLATE\r\n",
  "Ntfs": " ntfs.sys     -     SCB_DATA\r\n",
  "KSsl": " <unknown>    -    symbolic link buffer (MSKSSRV)\r\n",
  "LSdi": " srv.sys      -     SMB1 BlockTypeDirectoryInfo\r\n",
  "RxVn": " rdbss.sys - RDBSS VNetRoot\r\n",
  "RBEv": " <unknown>    - RedBook - Thread Events\r\n",
  "UlDC": " http.sys     - Data Chunks array\r\n",
  "Lfs ": " <unknown>    - Lfs allocations\r\n",
  "RSWQ": " <unknown>    -      Work Queue\r\n",
  "Isap": " <unknown>    - Pnp Isa bus extender\r\n",
  "WanB": " <unknown>    - ProtocolCB/LinkCB\r\n",
  "WanC": " <unknown>    - DataDesc\r\n",
  "WanA": " <unknown>    - BundleCB\r\n",
  "WanG": " <unknown>    - MiniportCB\r\n",
  "WanD": " <unknown>    - WanRequest\r\n",
  "WanE": " <unknown>    - LoopbackDesc\r\n",
  "WanJ": " <unknown>    - LineUpInfo\r\n",
  "WanK": " <unknown>    - Unicode String Buffer\r\n",
  "WanH": " <unknown>    - OpenCB\r\n",
  "WanI": " <unknown>    - IoPacket\r\n",
  "WanN": " <unknown>    - NdisPacketPool Desc\r\n",
  "WanL": " <unknown>    - Protocol Table\r\n",
  "MuSf": " mup.sys      - Surrogate file info\r\n",
  "ClNw": " netft.sys    - NetFt work items\r\n",
  "RxBm": " rdbss.sys - RDBSS buffering manager\r\n",
  "LfsI": " <unknown>    - Lfs allocations\r\n",
  "ClNt": " netft.sys    - NetFt\r\n",
  "WanV": " <unknown>    - RC4 Encryption Context\r\n",
  "WanW": " <unknown>    - SHA Encryption\r\n",
  "WanT": " <unknown>    - Transform Driver\r\n",
  "WanZ": " <unknown>    - Protocol Specific Info\r\n",
  "WanX": " <unknown>    - Send Compression Context\r\n",
  "WanY": " <unknown>    - Recv Compression Context\r\n",
  "UdCo": " tcpip.sys    - UDP Compartment\r\n",
  "I4sa": " tcpip.sys    - IPsec SADB v4\r\n",
  "Ntfu": " ntfs.sys     -     NTFS_MARK_UNUSED_CONTEXT\r\n",
  "CdFn": " cdfs.sys     - CDFS Filename buffer\r\n",
  "Umit": " win32kfull!SetLPITEMInfoNoRedraw - USERTAG_MENUITEM\r\n",
  "Icse": " tcpip.sys    - IPsec NS connection state\r\n",
  "PcUs": " <unknown>    - WDM audio stuff\r\n",
  "NBI ": " <unknown>    - NwlnkNb transport\r\n",
  "RfRX": " rfcomm.sys   -   RFCOMM receive\r\n",
  "Vbxp": " vmbus.sys    - Virtual Machine Bus Driver (cross partition)\r\n",
  "RLin": " <unknown>    - FsLib Range lock entry\r\n",
  "DEbo": " devolume.sys - Drive extender bus opener context: DEVolume!DEBusOpenerContext\r\n",
  "DEbm": " devolume.sys - Drive extender bitmap\r\n",
  "DEbg": " devolume.sys - Drive extender bus opener context global: DEVolume!DEBusOpenerContextGlobal\r\n",
  "DEbe": " devolume.sys - Drive extender extends buffer\r\n",
  "Usqu": " win32k!InitQEntryLookaside           - USERTAG_Q\r\n",
  "ScCa": " cdrom.sys    -      Media change detection\r\n",
  "Usqm": " win32k!InitQEntryLookaside           - USERTAG_QMSG\r\n",
  "Usql": " win32k!EnsureQMsgLog                 - USERTAG_QMSGLOG\r\n",
  "DEbu": " devolume.sys - Drive extender generic buffer\r\n",
  "ScLm": " classpnp.sys -      Mount\r\n",
  "SDd ": " smbdirect.sys - SMB Direct connect event contexts\r\n",
  "NDxc": " ndis.sys     - NDIS_TAG_POOL_XLATE\r\n",
  "ObCI": " nt!ob        - object creation lookaside list\r\n",
  "BTHP": " bthport.sys  - Bluetooth port driver (generic)\r\n",
  "Net ": " tcpip.sys    - NetIO Generic Buffers (iBFT Table allocations)\r\n",
  "Crsp": " ksecdd.sys   - CredSSP kernel mode client allocations\r\n",
  "Nmdd": " <unknown>    - NetMeeting display driver miniport 1 MB block\r\n",
  "UsDI": " win32k!CreateDeviceInfo              - USERTAG_DEVICEINFO\r\n",
  "NtFd": " ntfs.sys     -     DirCtrl.c\r\n",
  "IPlc": " tcpip.sys    - IP Locality\r\n",
  "ScPM": " <unknown>    -      scatter gather lists\r\n",
  "RBWa": " <unknown>    - RedBook - Wait block for system thread\r\n",
  "IPle": " tcpip.sys    - IP Loopback execution context\r\n",
  "IPlo": " tcpip.sys    - IP Loopback buffers\r\n",
  "IPlw": " tcpip.sys    - IP Loopback worker\r\n",
  "Pcic": " <unknown>    - Pcmcia bus enumerator, PCIC/Cardbus controller specific structures\r\n",
  "IbPm": " wibpm.sys - WIBPM_TAG Windows Infiniband Performance Manager\r\n",
  "Gnls": " win32k.sys                           - GDITAG_NLS\r\n",
  "IbPS": " wibpm.sys - WIBPM_SENT_TAG\r\n",
  "RSER": " <unknown>    -      Error log data\r\n",
  "UlFP": " http.sys     - Filter Process\r\n",
  "RaHI": " storport.sys - RaSaveDriverInitData storport!_HW_INITIALIZATION_DATA\r\n",
  "DmS?": " <unknown>    - DirectMusic kernel software synthesizer\r\n",
  "UlFU": " http.sys     - Full Tracker\r\n",
  "rb??": " <unknown>    - RedBook Filter Driver, dynamic allocations\r\n",
  "IoEa": " nt!io        - Io extended attributes\r\n",
  "CMSb": " nt!cm        - internal stash buffer pool tag\r\n",
  "KSfd": " <unknown>    -    filter cache data (MSKSSRV)\r\n",
  "VdMm": " Vid.sys - Virtual Machine Virtualization Infrastructure Driver (VSMM service)\r\n",
  "Ldmp": " nt!io        -     Live Dump Buffers. Note, these buffers will not be present in the resulting live dump file.\r\n",
  "IbPA": " wibpm.sys - WIBPM_SAMPLE_TAG\r\n",
  "PciB": " pci.sys      - PnP pci bus enumerator\r\n",
  "MQAD": " mqac.sys     - MSMQ driver, CDistribution allocations\r\n",
  "UlFA": " http.sys     - Force Abort Work Item\r\n",
  "MuFn": " mup.sys      - File name rewrite\r\n",
  "IbPI": " wibpm.sys - WIBPM_ITEM_TAG\r\n",
  "IoEr": " nt!io        - Io error log packets\r\n",
  "DCfe": " win32kbase!DirectComposition::CFilterEffectMarshaler::_allocate                          - DCOMPOSITIONTAG_FILTEREFFECTMARSHALER\r\n",
  "Ppei": " nt!pnp       - Eisa related code\r\n",
  "DCff": " win32kbase!DirectComposition::CFilterEffectMarshaler::Initialize                         - DCOMPOSITIONTAG_FILTERINPUTFLAGS\r\n",
  "PfET": " nt!pf        - Pf Entry info tables\r\n",
  "VsCs": " vmswitch.sys - Virtual Machine Network Switch Driver (configuration store)\r\n",
  "DCfo": " win32kbase!DirectComposition::CSpatialVisualMarshaler::_allocate                         - DCOMPOSITIONTAG_SPATIALVISUALMARSHALER\r\n",
  "DCfi": " win32kbase!DirectComposition::CFilterEffectMarshaler::Initialize                         - DCOMPOSITIONTAG_FILTERINPUTS\r\n",
  "IpCO": " ipsec.sys    -  IP compression\r\n",
  "DCfj": " win32kbase!DirectComposition::CFilterEffectMarshaler::Initialize                         - DCOMPOSITIONTAG_SUBRECTINPUTFLAGS\r\n",
  "PfED": " nt!pf        - Pf Generic event data\r\n",
  "UlLD": " http.sys     - Log Field\r\n",
  "UscI": " win32k!CitStart                      - USERTAG_COMPAT_IMPACT\r\n",
  "PfEL": " nt!pf        - Pf Event logging buffers\r\n",
  "Gxpd": " win32k!XUMPDOBJ::XUMPDOBJ            - GDITAG_UMPDOBJ\r\n",
  "DEpe": " devolume.sys - Drive extender pingable event: DEVolume!PingableEvent\r\n",
  "Uscp": " win32k!CreateDIBPalette              - USERTAG_CLIPBOARDPALETTE\r\n",
  "DEpg": " devolume.sys - Drive extender pingable object globals: DEVolume!PingableObjectGlobals\r\n",
  "Uscr": " win32k!NtUserSetSysColors            - USERTAG_COLORS\r\n",
  "VsCP": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney NBL context)\r\n",
  "CMIn": " nt!cm        - Configuration Manager  Index Hint Tag\r\n",
  "RxNc": " rdbss.sys - RDBSS name cache\r\n",
  "Uscv": " win32k!NtUserSetSysColors            - USERTAG_COLORVALUES\r\n",
  "DEpm": " devolume.sys - Drive extender physical map: DEVolume!PhysicalMap\r\n",
  "AzUT": " HDAudio.sys  - HD Audio Class Driver (TestSet0004)\r\n",
  "Nrtw": " netio.sys    - NRT worker\r\n",
  "UlEP": " http.sys     - Endpoint\r\n",
  "Usca": " win32k!NtUserSetCalibrationData      - USERTAG_CALIBRATIONDATA\r\n",
  "Gadd": " win32k.sys                           - GDITAG_DC_FONT\r\n",
  "Uscc": " win32k!AllocCallbackMessage          - USERTAG_CALLBACK\r\n",
  "CMIx": " nt!cm        - Configuration Manager Intent Lock Tag\r\n",
  "Usce": " win32k!RetrieveLinkCollection        - USERTAG_COLLINK\r\n",
  "Uscd": " win32k!GetCPD                        - USERTAG_CPD\r\n",
  "Gh??": " win32k.sys                           - GDITAG_HMGR_SPRITE_TYPE\r\n",
  "PmRP": " partmgr.sys  - Partition Manager registry path\r\n",
  "ScWs": " classpnp.sys - Working set\r\n",
  "Uscl": " win32k!ClassAlloc                    - USERTAG_CLASS\r\n",
  "Redf": " refs.sys     -     REFS_DISK_FLUSH_CONTEXT allocations\r\n",
  "Info": " <unknown>    - general system information allocations\r\n",
  "UlHV": " http.sys     - Header Value\r\n",
  "VsC6": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney path6 context)\r\n",
  "FMdl": " fltmgr.sys   -       Array of DEVICE_OBJECT pointers\r\n",
  "UlHR": " http.sys     - Internal Request\r\n",
  "Mmdl": " nt!mm        - Mm Mdls for flushes\r\n",
  "FMdh": " fltmgr.sys   -       Paged ECP context for targeted create reparse\r\n",
  "Gtvt": " win32k!bTriangleMesh                 - GDITAG_TRIANGLE_MESH\r\n",
  "DElv": " devolume.sys - Drive extender disk set volume id record: DEVolume!VolumeIdentificationRecord\r\n",
  "Reft": " refs.sys     -     SCB (Prerestart)\r\n",
  "VmRr": " volmgrx.sys  - Raw records\r\n",
  "Refc": " refs.sys     -     CCB_DATA\r\n",
  "UlHC": " http.sys     - Http Connection\r\n",
  "Gadb": " win32k!XDCOBJ::bAddColorTransform    - GDITAG_DC_COLOR_TRANSFORM\r\n",
  "LogA": " clfsapimp.sys - CLFS Kernel API test driver\r\n",
  "NDmt": " ndis.sys     - NDIS_TAG_MEDIA_TYPE_ARRAY\r\n",
  "smms": " nt!store     -         ReadyBoost virtual store memory monitor context\r\n",
  "UlHL": " http.sys     - Internal Request RefTraceLog\r\n",
  "SeGa": " nt!se        - Granted Access allocations\r\n",
  "DCto": " win32kbase!DirectComposition::CTelemetryInfo::_allocate                                  - DCOMPOSITIONTAG_TELEMETRYINFO\r\n",
  "Gapc": " win32kfull!UmfdQueueTryUnzombifyPffApc - GDITAG_UNZOMBIFY_APC\r\n",
  "Vi31": " dxgmms2.sys  - Video memory manager dummy page\r\n",
  "Ppsu": " nt!pnp       - plug-and-play subroutines for the I/O system\r\n",
  "Fl4D": " tcpip.sys    - FL4t DataLink Addresses\r\n",
  "ObCi": " nt!ob        - captured information for ObCreateObject\r\n",
  "DCtc": " win32kbase!DirectComposition::CTileClumpMarshaler::_allocate                             - DCOMPOSITIONTAG_TILECLUMPMARSHALER\r\n",
  "Navl": " tcpip.sys    - Network Layer AVL Tree allocations\r\n",
  "MQAP": " mqac.sys     - MSMQ driver, CPacket allocations\r\n",
  "LBxn": " <unknown>    -     TransportName\r\n",
  "DCtz": " win32kbase!DirectComposition::CTextBrushMarshaler::SetBufferProperty                     - DCOMPOSITIONTAG_TEXTCONTENT\r\n",
  "DCty": " win32kbase!DirectComposition::CTextBrushMarshaler::SetBufferProperty                     - DCOMPOSITIONTAG_TEXTFONTNAME\r\n",
  "LBxm": " <unknown>    -     Master name\r\n",
  "NMpt": " <unknown>    - Generic AVL Tree allocations\r\n",
  "DCts": " win32kbase!DirectComposition::_allocate                                                  - DCOMPOSITIONTAG_TELEMETRYSTRING\r\n",
  "DbCb": " nt!dbg       - Debug Print Callbacks\r\n",
  "ScCi": " cdrom.sys    -      Cached inquiry buffer\r\n",
  "VHtx": " vmusbhub.sys - Virtual Machine USB Hub Driver (text)\r\n",
  "FstB": " <unknown>    - ntos\\fstub\r\n",
  "PfAL": " nt!pf        - Pf Application launch event data\r\n",
  "PpWI": " nt!pnp       - PNP_DEVICE_WORK_ITEM_TAG\r\n",
  "p2fi": " perm2dll.dll - Permedia2 display driver - fillpath.c\r\n",
  "LS2o": " srv2.sys     -     SMB2 oplock break\r\n",
  "Vi37": " dxgmms2.sys  - Video memory manager DMA buffer global alloc table\r\n",
  "Fstb": " <unknown>    - ntos\\fstub\r\n",
  "GMFF": " win32k.sys                           - GDITAG_FONT_MAPPER_FAMILY_FALLBACK\r\n",
  "Ghmc": " win32k!GdiHandleManager::Create      - GDITAG_HANDLE_MANAGER\r\n",
  "Wrpr": " <unknown>    - WAN_REQUEST_TAG\r\n",
  "DCt3": " win32kbase!DirectComposition::CTranslateTransform3DMarshaler::_allocate                  - DCOMPOSITIONTAG_TRANSLATETRANSFORM3DMARSHALER\r\n",
  "Dxdd": " win32k!DxLddmSharedPrimaryLockNotification - GDITAG_LOCKED_PRIMARY\r\n",
  "Mup ": " mup.sys      - Multiple UNC provider allocations, generic\r\n",
  "CEP ": " wibcm.sys - CEP_INSTANCE_TAG\r\n",
  "ScCo": " cdrom.sys    -      Device Notification buffer\r\n",
  "Gi2c": " win32k.sys                           - GDITAG_DDCCI\r\n",
  "DChd": " win32kbase!DirectComposition::CHolographicDisplayMarshaler::_allocate                    - DCOMPOSITIONTAG_HOLOGRAPHICDISPLAYMARSHALER\r\n",
  "VVpc": " vhdparser.sys - Virtual Machine Storage VHD Parser Driver (context)\r\n",
  "USqm": " win32k!_WinSqmAllocate               - USERTAG_SQM\r\n",
  "DCoc": " win32kbase!DirectComposition::CContainerShapeMarshaler::_allocate                        - DCOMPOSITIONTAG_CONTAINERSHAPEMARSHALER\r\n",
  "Flop": " <unknown>    - floppy driver\r\n",
  "StCx": " netio.sys    - WFP stream internal callout context\r\n",
  "Lrxx": " <unknown>    -     Transceive context blocks\r\n",
  "SmTr": " mrxsmb10.sys    -      SMB1 transact exchange\r\n",
  "IoFs": " nt!io        - Io shutdown packet\r\n",
  "U802": " usb8023.sys  - RNDIS USB 8023 driver\r\n",
  "KSPI": " <unknown>    -    pin instance\r\n",
  "SIfs": " <unknown>    - Default tag for user's of ntsrv.h\r\n",
  "FMvf": " fltmgr.sys   -       FLT_VERIFIER_EXTENSION structure\r\n",
  "TdxI": " tdx.sys      - TDX IO Control Buffers\r\n",
  "FMvl": " fltmgr.sys   -       Array of FLT_VERIFIER_OBJECT structures\r\n",
  "FMvo": " fltmgr.sys   -       FLT_VOLUME structure\r\n",
  "FMvj": " fltmgr.sys   -       FLT_VERIFIER_OBJECT structure\r\n",
  "WPAO": " BasicRender.sys - Basic Render Opened Allocation\r\n",
  "WPAL": " BasicRender.sys - Basic Render Allocation\r\n",
  "Call": " nt!ex        - kernel callback object signature\r\n",
  "WPAD": " BasicRender.sys - Basic Render Adapter\r\n",
  "Vi19": " dxgmms2.sys  - Video memory manager pool block array\r\n",
  "Udp ": " <unknown>    - Udp protocol (TCP/IP driver)\r\n",
  "TWTs": " netiobvt.sys - BVT TW Generic Buffers\r\n",
  "Aric": " tcpip.sys    -     ALE route inspection context\r\n",
  "p2he": " perm2dll.dll - Permedia2 display driver - heap.c\r\n",
  "RxCr": " rdbss.sys - RDBSS credential\r\n",
  "RxCo": " rdbss.sys - RDBSS construction context\r\n",
  "VM  ": " volmgr.sys   - General allocations\r\n",
  "FSim": " nt!fsrtl     - File System Run Time Mcb Initial Mapping Lookaside List\r\n",
  "G   ": " <unknown>    -     Gdi Generic allocations\r\n",
  "MuIc": " mup.sys      - IRP Context\r\n",
  "Gcsl": " win32k!InitializeScripts             - GDITAG_SCRIPTS\r\n",
  "Pgm?": " <unknown>    - Pgm (Pragmatic General Multicast) protocol: RMCast.sys\r\n",
  "I4rd": " tcpip.sys    - IPv4 Receive Datagrams Arguments\r\n",
  "RxCa": " mrxsmb.sys - RXCE address\r\n",
  "IMsg": " win32k!CInputManager::Create                         - INPUTMANAGER_SESSIONGLOBAL\r\n",
  "DCac": " win32kbase!DirectComposition::CApplicationChannel::_allocate                             - DCOMPOSITIONTAG_APPLICATIONCHANNEL\r\n",
  "DCsl": " win32kbase!DirectComposition::CScalarMarshaler::_allocate                                - DCOMPOSITIONTAG_SCALARMARSHALER\r\n",
  "ScPA": " <unknown>    -      Access Ranges\r\n",
  "ScCs": " cdrom.sys    -      Assorted string data\r\n",
  "Udf4": " udfs.sys     - Udfs logical volume integrity descriptor buffer\r\n",
  "Afp ": " <unknown>    - SFM File server\r\n",
  "PmPT": " partmgr.sys  - Partition Manager partition table cache\r\n",
  "NDlp": " ndis.sys     - NDIS_TAG_LOOP_PKT\r\n",
  "SmSh": " mrxsmb.sys    - SMB shadow file (fast loopback)\r\n",
  "InPa": " tcpip.sys    - Inet Port Assignments\r\n",
  "Vkou": " vmbkmcl.sys  - Hyper-V VMBus KMCL driver (outgoing packets)\r\n",
  "SWpd": " <unknown>    -         POOLTAG_DEVICE_PDOEXTENSION\r\n",
  "FLli": " <unknown>    - per-file lock information\r\n",
  "ScCr": " cdrom.sys    -      Registry string\r\n",
  "RfAD": " rfcomm.sys   -   RFCOMM Address\r\n",
  "NDlb": " ndis.sys     -     lookahead buffer\r\n",
  "PpUB": " nt!pnp       - PNP_USER_BLOCK_TAG\r\n",
  "Dwd ": " <unknown>    - wd90c24a video driver\r\n",
  "Lrna": " <unknown>    -     Netbios Addresses\r\n",
  "CmcK": " hal.dll      - HAL CMC Kernel Log\r\n",
  "UNbl": " tcpip.sys    - UDP NetBufferLists\r\n",
  "Lrnf": " <unknown>    -     Non paged FCB\r\n",
  "VmRm": " volmgrx.sys  - RAID-5 emergency mappings\r\n",
  "InPA": " tcpip.sys    - Inet Port Assignment Arrays\r\n",
  "UdpN": " tcpip.sys    - UDP Name Service Interfaces\r\n",
  "InPE": " tcpip.sys    - Inet Port Exclusions\r\n",
  "CmcD": " hal.dll      - HAL CMC Driver Log\r\n",
  "MSTa": " <unknown>    -    associated stream header\r\n",
  "ALPC": " nt!alpc      - ALPC port objects\r\n",
  "NSpg": " nsi.dll      - NSI Proxy Generic Buffers\r\n",
  "NDfv": " ndis.sys     - NDIS_TAG_LWFILTER_DRIVER\r\n",
  "Lrnt": " <unknown>    -     Non paged transport\r\n",
  "NSpc": " nsi.dll      - NSI Proxy Contexts\r\n",
  "InPP": " tcpip.sys    - Inet Port pool\r\n",
  "VPrs": " passthruparser.sys - Virtual Machine Storage Passthrough Parser Driver\r\n",
  "CmcT": " hal.dll      - HAL CMC temporary Log\r\n",
  "CMnb": " nt!cm        - registry notify blocks\r\n",
  "Vkin": " vmbkmcl.sys  - Hyper-V VMBus KMCL driver (incoming packets)\r\n",
  "IMhq": " win32k!CInputQueue::Create                           - INPUTMANAGER_INPUTQUEUE\r\n",
  "Gh?>": " win32k.sys                           - GDITAG_HMGR_ICMCXF_TYPE\r\n",
  "Petw": " pacer.sys    - PACER ETW\r\n",
  "LS2W": " srv2.sys     -     SMB2 special workitem\r\n",
  "Ttfd": " win32k.sys                           - GDITAG_TT_FONT\r\n",
  "ScR?": " <unknown>    -   Partition Manager\r\n",
  "LS2c": " srv2.sys     -     SMB2 connection\r\n",
  "LS2b": " srv2.sys     -     SMB2 buffer\r\n",
  "LS2e": " srv2.sys     -     SMB2 endpoint\r\n",
  "Uslr": " win32k!InitLockRecordLookaside       - USERTAG_LOCKRECORD\r\n",
  "Dlck": " <unknown>    - deadlock verifier (part of driver verifier) structures\r\n",
  "LS2f": " srv2.sys     -     SMB2 file\r\n",
  "LS2i": " srv2.sys     -     SMB2 client\r\n",
  "LS2h": " srv2.sys     -     SMB2 share\r\n",
  "ObWm": " nt!ob        - Object Manager wait blocks\r\n",
  "LS2l": " srv2.sys     -     SMB2 lease\r\n",
  "Gcac": " win32k.sys                           - GDITAG_FONTCACHE\r\n",
  "LS2n": " srv2.sys     -     SMB2 channel\r\n",
  "LS2q": " srv2.sys     -     SMB2 queue\r\n",
  "LS2p": " srv2.sys     -     SMB2 provider\r\n",
  "LS2s": " srv2.sys     -     SMB2 session\r\n",
  "DCjb": " win32kbase!DirectComposition::CBackdropBrushMarshaler::_allocate                         - DCOMPOSITIONTAG_BACKDROPBRUSHMARSHALER\r\n",
  "IKeO": " tcpip.sys    - IPsec key object\r\n",
  "LS2t": " srv2.sys     -     SMB2 treeconnect\r\n",
  "LS2w": " srv2.sys     -     SMB2 workitem\r\n",
  "NbtI": " netbt.sys    - NetBT listen requests\r\n",
  "LS2x": " srv2.sys     -     SMB2 security context\r\n",
  "Gcap": " <unknown>    -     Gdi capture buffer\r\n",
  "Ntfi": " ntfs.sys     -     IRP_CONTEXT\r\n",
  "IoFu": " nt!pnp       - Io file utils\r\n",
  "IbW0": " wibwmi.sys - WIBWMI0_TAG Windows Infiniband WMI Manager\r\n",
  "IbW1": " wibwmi.sys - WIBWMI1_TAG\r\n",
  "IbW2": " wibwmi.sys - WIBWMI2_TAG\r\n",
  "FtpA": " mpsdrv.sys   - MPSDRV FTP protocol analyzer\r\n",
  "ppRT": " pvhdparser.sys - Proxy Virtual Machine Storage VHD Parser Driver (parser)\r\n",
  "NS??": " <unknown>    - Netware server allocations\r\n",
  "Gpfe": " win32k!PFFMEMOBJ::bAllocPFEData      - GDITAG_PFF_INDEXES\r\n",
  "NbtL": " netbt.sys    - NetBT datagram\r\n",
  "ScCv": " cdrom.sys    -      Read buffer for rpc2 check\r\n",
  "VmTx": " volmgrx.sys  - Transactions\r\n",
  "DChs": " win32kbase!DirectComposition::CSharedHolographicInteropTextureMarshaler::_allocate       - DCOMPOSITIONTAG_SHAREDHOLOGRAPHICINTEROPTEXTUREMARSHALER\r\n",
  "Dh 0": " <unknown>    - DirectDraw/3D default object\r\n",
  "Dh 1": " <unknown>    - DirectDraw/3D DirectDraw object\r\n",
  "Dh 2": " <unknown>    - DirectDraw/3D Surface object\r\n",
  "Dh 3": " <unknown>    - DirectDraw/3D Direct3D context object\r\n",
  "Dh 4": " <unknown>    - DirectDraw/3D VideoPort object\r\n",
  "Dh 5": " <unknown>    - DirectDraw/3D MotionComp object\r\n",
  "WlLb": " writelog.sys - Writelog library buffer\r\n",
  "VidR": " videoprt.sys - VideoPort Allocation on behalf of Miniport\r\n",
  "SDc ": " smbdirect.sys - SMB Direct MR buffers\r\n",
  "Vi02": " dxgmms2.sys  - Video memory manager local alloc\r\n",
  "RSVO": " <unknown>    -      Validate Queue\r\n",
  "SWfd": " <unknown>    -         POOLTAG_DEVICE_FDOEXTENSION\r\n",
  "LS2$": " srv2.sys     -     SMB2 misc. allocation\r\n",
  "Dqv ": " <unknown>    - qv (qvision) video driver\r\n",
  "WofH": " wof.sys      - Wof handle context\r\n",
  "PsAp": " nt!ps        - Process APC queued by user mode process\r\n",
  "DCjl": " win32kbase!DirectComposition::CLinearGradientBrushMarshaler::_allocate                   - DCOMPOSITIONTAG_LINEARGRADIENTBRUSHMARSHALER\r\n",
  "LS20": " srvnet.sys   -     SRVNET LookasideList level 20 allocation 832K Bytes\r\n",
  "Pcfl": " pacer.sys    - PACER Flows\r\n",
  "Ntfk": " ntfs.sys     -     FILE_LOCK\r\n",
  "VfIT": " nt!Vf        - Verifier Import Address Table information\r\n",
  "EtwW": " nt!etw       - Etw WorkItem\r\n",
  "EtwT": " nt!etw       - Etw provider traits\r\n",
  "EtwU": " nt!etw       - Etw Periodic Capture State\r\n",
  "CmVn": " nt!cm        - captured value name\r\n",
  "EtwS": " nt!etw       - Etw DataSource\r\n",
  "EtwP": " nt!etw       - Etw Pool\r\n",
  "Ucte": " http.sys     - Entity Pool\r\n",
  "Txre": " ntfs.sys     - TXF_TOPS_RANGE_ENTRY\r\n",
  "Envr": " <unknown>    - Environment strings\r\n",
  "EtwZ": " nt!etw       - Etw compression support\r\n",
  "UlTA": " http.sys     - Address Pool\r\n",
  "EtwX": " nt!etw       - Etw profiling support\r\n",
  "EtwF": " nt!etw       - Etw Filter\r\n",
  "EtwG": " nt!etw       - Etw Guid\r\n",
  "EtwD": " nt!etw       - Etw DataBlock\r\n",
  "RaEW": " tcpip.sys    - Raw Socket Endpoint Work Queue Contexts\r\n",
  "EtwB": " nt!etw       - Etw Buffer\r\n",
  "EtwC": " nt!etw       - Etw Realtime Consumer\r\n",
  "RBRl": " <unknown>    - RedBook - Remove lock\r\n",
  "EtwA": " nt!etw       - Etw APC\r\n",
  "EtwL": " nt!etw       - Etw LoggerContext\r\n",
  "VmRc": " volmgrx.sys  - Raw configurations\r\n",
  "EtwK": " nt!etw       - Etw SoftRestart support\r\n",
  "EtwH": " nt!etw       - Etw Private Handle Demuxing\r\n",
  "DCck": " win32kbase!DirectComposition::CBaseExpressionMarshaler::SetBufferProperty                - DCOMPOSITIONTAG_DEBUGTAG\r\n",
  "Etwt": " nt!etw       - Etw temporary buffer\r\n",
  "IneI": " tcpip.sys    - Inet Inspects\r\n",
  "IIwc": " <unknown>    - Work Context\r\n",
  "Etws": " nt!etw       - Etw stack cache\r\n",
  "Etwp": " nt!etw       - Etw TracingBlock\r\n",
  "Etwq": " nt!etw       - Etw ReplyQueue\r\n",
  "Refd": " refs.sys     -     DEALLOCATED_CLUSTERS\r\n",
  "VsC4": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney path4 context)\r\n",
  "Obtb": " nt!ob        - object tables via EX handle.c\r\n",
  "Usri": " win32k!NtUserRegisterRawInputDevices - USERTAG_RAWINPUTDEVICE\r\n",
  "RaEt": " storport.sys - RaidBusEnumeratorProcessBusUnit\r\n",
  "KSCI": " <unknown>    -    clock instance\r\n",
  "Etwb": " nt!etw       - Etw provider tracking\r\n",
  "Etwc": " nt!etw       - Etw rundown reference counters\r\n",
  "vDMW": " dmvsc.sys - Virtual Machine Dynamic Memory VSC Driver (WDF)\r\n",
  "Etwa": " nt!etw       - Etw server silo state\r\n",
  "virt": " vmm.sys      - Virtual Machine Manager (VPC/VS)\r\n",
  "VmRb": " volmgrx.sys  - Raw record buffers\r\n",
  "Etwl": " nt!etw       - Etw stack look-aside list entry\r\n",
  "Etwm": " nt!etw       - Etw BitMap\r\n",
  "DCwt": " win32kbase!DirectComposition::CApplicationChannel::GetWeakReferenceBase                  - DCOMPOSITIONTAG_WEAKREFERENCETABLEENTRY\r\n",
  "Uspc": " win32k!CreatePointerDeviceInfo       - USERTAG_POINTERDEVICE\r\n",
  "MuUn": " mup.sys      - UNC provider\r\n",
  "CcVp": " nt!cc        - Cache Manager Array of Vacb pointers for a cached stream\r\n",
  "DEag": " devolume.sys - Drive extender disk set array: DEVolume!DEDiskSet *\r\n",
  "D851": " <unknown>    - 8514a video driver\r\n",
  "I4nb": " tcpip.sys    - IPv4 Neighbors\r\n",
  "CcVl": " nt!cc        - Cache Manager Vacb Level structures (large streams)\r\n",
  "IBCM": " wibcm.sys - CM_INSTANCE_TAG Windows Infiniband Communications Manager\r\n",
  "Gfda": " win32k!UmfdAllocation::Create        - GDITAG_UMFD_ALLOCATION\r\n",
  "Ugwm": " win32kfull!CWindowGroup::operator new - USERTAG_GROUP_WINDOW_MANAGEMENT\r\n",
  "Gfdf": " win32k!InitializeDefaultFamilyFonts  - GDITAG_FONT_DEFAULT_FAMILY\r\n",
  "NEPK": " newt_ndis6.sys - NEWT Packet\r\n",
  "I6nb": " tcpip.sys    - IPv6 Neighbors\r\n",
  "VHDo": " vhdmp.sys    - VHD footer\r\n",
  "Usih": " win32k!SetImeHotKey                  - USERTAG_IMEHOTKEY\r\n",
  "MSro": " refs.sys     - Minstore container rotation buffer\r\n",
  "Giga": " win32k.sys                           - GDITAG_PRIVATEGAMMA\r\n",
  "MSrm": " refs.sys     - Minstore range map\r\n",
  "MSrk": " refs.sys     - Minstore key rules\r\n",
  "Reff": " refs.sys     -     FCB_DATA\r\n",
  "MRXx": " <unknown>    - Client side caching for SMB\r\n",
  "MSre": " refs.sys     - Minstore AVL lite entries (incl. and primarily SmsRangeMapEntry)\r\n",
  "MSrb": " refs.sys     - Minstore redo block\r\n",
  "MSrc": " refs.sys     - Minstore tx run cache\r\n",
  "FDpd": " win32k.sys                           - GDITAG_UMFD_PDEV\r\n",
  "MSrv": " refs.sys     - Minstore reserved buffers\r\n",
  "RaPD": " storport.sys - RaidGetPortData storport!RaidpPortData\r\n",
  "MSrr": " refs.sys     - Minstore AVL lite entries (incl. and primarily SmsRCRangeMapEntry)\r\n",
  "MSrp": " refs.sys     - Minstore read cache pages array\r\n",
  "TMsg": " dxgkrnl!CreateSessionTokenManager                     - TOKENMANAGER_SESSIONGLOBAL\r\n",
  "DCcx": " win32kbase!DirectComposition::CSharedWriteCaptureControllerMarshaler::_allocate          - DCOMPOSITIONTAG_WRITECAPTURECONTROLLERMARSHALER\r\n",
  "Ufsc": " <unknown>    - User FULLSCREEN\r\n",
  "Asy4": " <unknown>    - ndis / ASYNC_FRAME_TAG\r\n",
  "Asy3": " <unknown>    - ndis / ASYNC_ADAPTER_TAG\r\n",
  "dcam": " <unknown>    - WDM mini driver for IEEE 1394 digital camera\r\n",
  "Asy1": " <unknown>    - ndis / ASYNC_IOCTX_TAG\r\n",
  "TunK": " <unknown>    - Tunnel cache temporary key value\r\n",
  "smR?": " nt!store     -         ReadyBoost virtual forward progress resources\r\n",
  "Gdtd": " win32k!GreAcquireSemaphoreAndValidate - GDITAG_SEMAPHORE_VALIDATE\r\n",
  "rbRx": " <unknown>    - RedBook - Read Xtra info\r\n",
  "TunL": " <unknown>    - Tunnel cache lookaside-allocated elements\r\n",
  "GFil": " win32k.sys                           - GDITAG_FILEPATH\r\n",
  "EtwR": " nt!etw       - Etw KM RegEntry\r\n",
  "FVE0": " fvevol.sys   - General allocations\r\n",
  "Vprt": " videoprt.sys - Video port for legacy (pre-Vista) display drivers\r\n",
  "DCct": " win32kbase!DirectComposition::CApplicationChannel::AllocateTableEntry                    - DCOMPOSITIONTAG_CHANNELTABLE\r\n",
  "FCpi": " dxgkrnl!CreateFlipPropertySet - FLIPCONTENT_PROPERTYBLOBINDEXBUFFER\r\n",
  "Tun4 ": " <unknown>   - Tunnel cache allocation for long file name\r\n",
  "DCvc": " win32kbase!DirectComposition::CVisualMarshaler::AllocateChildrenArray                    - DCOMPOSITIONTAG_VISUALMARSHALERCHILDREN\r\n",
  "UsKe": " win32k!CreateKernelEvent             - USERTAG_KEVENT\r\n",
  "Gfsf": " win32k!bInitStockFontsInternal       - GDITAG_FONT_STOCKFONT\r\n",
  "AlEv": " nt!alpc      - ALPC eventlog queue\r\n",
  "ScPr": " <unknown>    -      resource list copy\r\n",
  "VHDy": " vhdmp.sys    - VHD dynamic header\r\n",
  "DCcp": " win32kbase!DirectComposition::CPushLockCriticalSection::_allocate                        - DCOMPOSITIONTAG_PUSHLOCKCRITICALSECTION\r\n",
  "Gh?0": " win32k.sys                           - GDITAG_HMGR_DEF_TYPE\r\n",
  "Wnf ": " nt!wnf       - Windows Notification Facility\r\n",
  "BTUR": " bthuart.sys  - Bluetooth UART minidriver\r\n",
  "ODMg": " dxgkrnl.sys  - Output Duplication component\r\n",
  "DCab": " win32kbase!DirectComposition::CAnimationBinding::_allocate                               - DCOMPOSITIONTAG_ANIMATIONBINDING\r\n",
  "Ahca": " ahcache.sys  -     Appcompat kernel cache pool tag\r\n",
  "DCae": " win32kbase!DirectComposition::CAnimationMarshaler::SetBufferProperty                     - DCOMPOSITIONTAG_ANIMATIONTIMEEVENTDATA\r\n",
  "DCag": " win32kbase!DirectComposition::CAnimationMarshaler::SetBufferProperty                     - DCOMPOSITIONTAG_ANIMATIONSCENARIOGUID\r\n",
  "SrOI": " sr.sys       -         Overwrite information\r\n",
  "fpgn": " wof.sys      - Compressed file general\r\n",
  "AzTs": " HDAudio.sys  - HD Audio Class Driver (TestSet1000, TestSet1001)\r\n",
  "Driv": " <unknown>    - Driver objects\r\n",
  "DCal": " win32kbase!DirectComposition::CAnimationTimeList::_allocate                              - DCOMPOSITIONTAG_ANIMATIONTIMELIST\r\n",
  "DCam": " win32kbase!DirectComposition::CCompositionAmbientLight::_allocate                        - DCOMPOSITIONTAG_AMBIENTLIGHTMARSHALER\r\n",
  "DCan": " win32kbase!DirectComposition::CAnimationMarshaler::_allocate                             - DCOMPOSITIONTAG_ANIMATIONMARSHALER\r\n",
  "Uskd": " win32k!xxxCreateDesktopEx2           - USERTAG_KERNELDESKTOPINFO\r\n",
  "ScB1": " classpnp.sys -  Query registry parameters\r\n",
  "ScB2": " classpnp.sys -  Registry path\r\n",
  "ScB4": " classpnp.sys -  Storage descriptor header\r\n",
  "ScB5": " classpnp.sys -  FDO relations\r\n",
  "BT8x": " <unknown>    - WDM mini drivers for Brooktree 848,829, etc.\r\n",
  "rbIp": " <unknown>    - RedBook - Irp pointer block\r\n",
  "DCay": " win32kbase!DirectComposition::CAnalogTextureTargetMarshaler::_allocate                   - DCOMPOSITIONTAG_ANALOGTEXTURETARGETMARSHALER\r\n",
  "DCaz": " win32kbase!DirectComposition::CAnalogCompositorMarshaler::_allocate                      - DCOMPOSITIONTAG_ANALOGCOMPOSITORMARSHALER\r\n",
  "smIt": " nt!store or rdyboost.sys - ReadyBoost store ETA timers\r\n",
  "Vib1": " dxgmms2.sys  - GPU scheduler flip queue entry\r\n",
  "IpBP": " ipsec.sys    -  buffer pools\r\n",
  "Gldv": " win32k.sys                           - GDITAG_LDEV\r\n",
  "Gfvi": " win32k!bUnloadAllButPermanentFonts   - GDITAG_FONTVICTIM\r\n",
  "Uslt": " win32k!InitializeWin32PoolTracking   - USERTAG_LEAKEDTAG\r\n",
  "DEwi": " devolume.sys - Drive extender work item: DEVolume!AutoWorkItem\r\n",
  "WofS": " wof.sys      - Wof stream context\r\n",
  "Ghtc": " win32k!bSetHTSrcSurfInfo             - GDITAG_HALFTONE_COLORTRIAD\r\n",
  "CSMb": " dxgkrnl!CCompositionBuffer::Create        - COMPOSITIONSURFACEMANAGER_BUFFER\r\n",
  "SdpC": " bthport.sys  -     Bluetooth SDP client connection\r\n",
  "SdpD": " bthport.sys  -     Bluetooth SDP database\r\n",
  "NbL2": " netbt.sys    - NetBT lower connection\r\n",
  "SdpI": " bthport.sys  -     Bluetooth port driver (SDP)\r\n",
  "smRW": " rdyboost.sys -         ReadyBoot read-after-write ranges\r\n",
  "smRT": " rdyboost.sys -         ReadyBoot thread params\r\n",
  "Gla0": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_START\r\n",
  "StTc": " storport.sys - PortTraceInitTracing storport!_STORAGE_TRACE_CONTEXT_INTERNAL\r\n",
  "CSMr": " dxgkrnl!CBufferRealization::Create        - COMPOSITIONSURFACEMANAGER_REALIZATION\r\n",
  "NDmr": " ndis.sys     -     map register entry array\r\n",
  "LStr": " srv.sys      -     SMB1 transaction\r\n",
  "RfBT": " rfcomm.sys   -   RFCOMM (bthport)\r\n",
  "ReFs": " refs.sys     -     StrucSup.c\r\n",
  "IPX ": " <unknown>    - Nwlnkipx transport\r\n",
  "RfBB": " rfcomm.sys   -   RFCOMM BRB\r\n",
  "VHuW": " vmusbhub.sys - Virtual Machine USB Hub Driver (WDF)\r\n",
  "NDmb": " ndis.sys     -     MAC block\r\n",
  "LStc": " srv.sys      -     SMB1 tree connect\r\n",
  "LStb": " srv.sys      -     SMB1 table\r\n",
  "ReFa": " refs.sys     -     AllocSup.c\r\n",
  "XDR?": " rpcxdr.sys   - NFS (Network File System) XDR driver\r\n",
  "CMsb": " nt!cm        - registry stash buffer\r\n",
  "Idst": " tcpip.sys    - IPsec DoS Protection state entry\r\n",
  "LSti": " srv.sys      -     SMB1 timer\r\n",
  "ReFf": " refs.sys     -     FsCtrl.c\r\n",
  "SFMb": " win32k!SfmTokenArray::EnsureTokenBufferSize - GDITAG_TOKENARRAY\r\n",
  "ReEv": " <unknown>    - Resource Event\r\n",
  "VHub": " vmusbhub.sys - Virtual Machine USB Hub Driver (Bus)\r\n",
  "ReFS": " refs.sys     -     SecurSup.c\r\n",
  "ReFU": " refs.sys     -     usnsup.c\r\n",
  "BCDK": " nt!init      - Kernel boot configuration data.\r\n",
  "ATFb": " AppTag file id buffer\r\n",
  "ReFH": " refs.sys     -     SelfHeal.c\r\n",
  "wpxp": " wof.sys      - Wim xpress context\r\n",
  "Ilom": " tcpip.sys    - IPsec LBFO offload map\r\n",
  "ReFA": " refs.sys     -     AttrHelpers.c\r\n",
  "ReFC": " refs.sys     -     Create.c\r\n",
  "V2sr": " vhdmp.sys    - VHD2 SRB range allocation\r\n",
  "ReFE": " refs.sys     -     Ea.c\r\n",
  "Ilog": " tcpip.sys    - IPsec LBFO offload general\r\n",
  "ReFF": " refs.sys     -     FileInfo.c\r\n",
  "@MP ": " <unknown>    - (Intel video driver) Miniport related memory\r\n",
  "Txlf": " ntfs.sys     - TXF_FCB (large)\r\n",
  "NDnc": " ndis.sys     - NDIS_TAG_NBL_CONTEXT\r\n",
  "Rx??": " rdbss.sys - RDBSS allocations\r\n",
  "ReF?": " refs.sys     -     Unknown ReFS source module\r\n",
  "Gglb": " <unknown>    -     Gdi temp buffer\r\n",
  "NBFr": " <unknown>    - NBF request\r\n",
  "TMcc": " dxgkrnl!CAdapterCollection::Create                    - TOKENMANAGER_ADAPTERCOLLECTION\r\n",
  "Usrd": " win32k!StoreRawDataBlock             - USERTAG_POINTERRAWDATA\r\n",
  "UsDt": " win32k!NtUserCtxDisplayIOCtl         - USERTAG_DISPLAYIOCTL\r\n",
  "DCeg": " win32kbase!DirectComposition::CEffectGroupMarshaler::_allocate                           - DCOMPOSITIONTAG_EFFECTGROUPMARSHALER\r\n",
  "PmAT": " partmgr.sys  - Partition Manager attributes table cache\r\n",
  "Ggly": " win32k.sys                           - GDITAG_HGLYPH\r\n",
  "Rf??": " <unknown>    - Bluetooth RFCOMM TDI driver\r\n",
  "Txls": " ntfs.sys     - TXF_CANCEL_LSN\r\n",
  "Ggls": " win32k.sys                           - GDITAG_GLYPHSET\r\n",
  "InAD": " tcpip.sys    - Inet Ancillary Data\r\n",
  "NBFq": " <unknown>    - NBF query buffer\r\n",
  "Gpan": " win32k.sys                           - GDITAG_PANNING_PDEV\r\n",
  "NBFo": " <unknown>    - NBF config data\r\n",
  "HTab": " <unknown>    - Hash Table pool\r\n",
  "Tths": " tcpip.sys    - TCP TFO histogram\r\n",
  "NBFl": " <unknown>    - NBF link object\r\n",
  "DEus": " devolume.sys - Drive extender unicode string\r\n",
  "GDev": " win32k.sys                           - GDITAG_PDEV\r\n",
  "DV??": " <unknown>    - RDR2 DAV MiniRedir Tags\r\n",
  "vS3W": " vms3cap.sys - Virtual Machine Emulated S3 Device Cap Driver (WDF)\r\n",
  "VmDh": " volmgrx.sys  - Disk headers\r\n",
  "MmAc": " nt!mm        - Mm access log buffers\r\n",
  "VmDd": " volmgrx.sys  - Disk devices\r\n",
  "VmDc": " volmgrx.sys  - Device changes\r\n",
  "NBFk": " <unknown>    - NBF loopback buffer\r\n",
  "IoFc": " nt!io        - Io name transmogrify operation\r\n",
  "Geto": " win32k.sys                           - GDITAG_TEXTOUT\r\n",
  "Tdxm": " tdx.sys      - TDX Transport Layer TDI Mappings\r\n",
  "NDSD": " ndis.sys     - NDIS_SETUP_DEVICE_EXTENSION\r\n",
  "DrDr": " rdpdr.sys    - Global object\r\n",
  "UsWP": " win32k!SetGlobalWallpaperSettings    - USERTAG_WALLPAPER\r\n",
  "SwMi": " <unknown>    - SWMidi KS filter (WDM Audio)\r\n",
  "VflW": " vmstorfl.sys - Virtual Machine Storage Filter Driver (WDF)\r\n",
  "MSag": " refs.sys     - Minstore unspecified AVL entries (too big for lookasides; filtered AVL)\r\n",
  "PmRR": " partmgr.sys  - Partition Manager removal relations\r\n",
  "TcUD": " tcpip.sys    - TCP Urgent Delivery Buffers\r\n",
  "MSah": " refs.sys     - Minstore allocator history\r\n",
  "Lraw": " <unknown>    -     Async write context\r\n",
  "LSfR": " srv2.sys     -     SMB2 rfssequence table and rfs64table\r\n",
  "LSfn": " srv.sys      -     SMB1 BlockTypeFSName\r\n",
  "SWrp": " <unknown>    -         reparse string\r\n",
  "PpLg": " nt!pnp       - PnP last good.\r\n",
  "Etwd": " nt!etw       - Etw Disallow List Entry\r\n",
  "Vflt": " vmstorfl.sys - Virtual Machine Storage Filter Driver\r\n",
  "Usrr": " win32k!TouchTargetingRankForRegion   - USERTAG_RANKFORRGN\r\n",
  "IIhd": " <unknown>    - Header\r\n",
  "Ps  ": " nt!ps        - general ps allocations\r\n",
  "WmGE": " <unknown>    - Wmi GuidEntry chunks\r\n",
  "Ghtm": " win32k.sys                           - GDITAG_HMGR_TEMP\r\n",
  "DCs3": " win32kbase!DirectComposition::CScaleTransform3DMarshaler::_allocate                      - DCOMPOSITIONTAG_SCALETRANSFORM3DMARSHALER\r\n",
  "MsFn": " <unknown>    - Mailslot temporary name buffer\r\n",
  "L2CA": " bthport.sys  - Bluetooth port driver (L2CAP)\r\n",
  "Itok": " tcpip.sys    - IPsec token\r\n",
  "MsFf": " <unknown>    - Mailslot FCB, File control block, Service side block for each created mailslot.\r\n",
  "MsFg": " <unknown>    - Mailslot global resource\r\n",
  "MsFd": " <unknown>    - Mailslot data entry write buffer, This is writes buffered inside mailslots\r\n",
  "DCwr": " win32kbase!DirectComposition::CWeakReferenceBase::_allocate                              - DCOMPOSITIONTAG_WEAKREFERENCE\r\n",
  "Luaf": " luafv.sys    - LUA File Virtualization\r\n",
  "FLsh": " <unknown>    - shared file lock\r\n",
  "MsFr": " <unknown>    - Mailslot read buffer, buffer created for pended reads issued.\r\n",
  "SYSA": " <unknown>    - Sysaudio (wdm audio)\r\n",
  "MsFw": " <unknown>    - Mailslot work context block, blocks create when we need to timeout reads.\r\n",
  "MsFt": " <unknown>    - Mailslot query template, used for directory queries.\r\n",
  "Gebr": " win32k!EngRealizeBrush               - GDITAG_ENGBRUSH\r\n",
  "ItoC": " tcpip.sys    - IPsec task offload context\r\n",
  "Vm  ": " volmgrx.sys  - General allocations\r\n",
  "MsFN": " <unknown>    - Mailslot FCB name buffer, name for each created mailslot\r\n",
  "ItoD": " tcpip.sys    - IPsec task offload delete SA\r\n",
  "NDcn": " ndis.sys     - NDIS_TAG_CANCEL_DEVICE_NAME\r\n",
  "MsFC": " <unknown>    - Mailslot root CCB, A client control block for the top level mailslot directory\r\n",
  "ItoO": " tcpip.sys    - IPsec task offload paramters\r\n",
  "MsFD": " <unknown>    - Mailslot root DCB and its name buffer\r\n",
  "ItoM": " tcpip.sys    - IPsec task offload interface\r\n",
  "ItoS": " tcpip.sys    - IPsec task offload add SA\r\n",
  "PSTA": " nt!po        - Po registered system state\r\n",
  "PRFd": " nt!wdi       - Performance Diagnostics Structures\r\n",
  "TAPI": " <unknown>    - ntos\\ndis\\ndistapi\r\n",
  "WmIS": " <unknown>    - Wmi InstanceSet chunks\r\n",
  "NDA ": " ndis.sys     - NDIS PacketDirect tag prefix\r\n",
  "NDch": " ndis.sys     - NDIS_TAG_CONFIG_HANDLE\r\n",
  "CcWq": " nt!cc        - Cache Manager Work Queue Item\r\n",
  "Qpfd": " <unknown>    -      FragmentDb\r\n",
  "CcWk": " nt!cc        - Kernel Cache Manager lookaside list\r\n",
  "RfDA": " rfcomm.sys   -   RFCOMM data\r\n",
  "I6ma": " tcpip.sys    - IPv6 Local Multicast Addresses\r\n",
  "krpc": " nt           - NTOS midl_user_allocate\r\n",
  "Ksec": " ksecdd.sys   - Security device driver\r\n",
  "RcpI": " sacdrv.sys -     Internal memory mgr initial heap block\r\n",
  "NbTA": " netbt.sys    - NetBT internal address\r\n",
  "IpSQ": " ipsec.sys    -  stall queues\r\n",
  "KseZ": " ksecdd.sys   - Security driver allocs for default sec package\r\n",
  "RcpA": " sacdrv.sys -     Internal memory mgr alloc block\r\n",
  "wprd": " wof.sys      - Wim small read buffer\r\n",
  "KseS": " ksecdd.sys   - Security driver allocs for LSA proper\r\n",
  "Gspm": " win32k.sys                           - GDITAG_METASPRITE\r\n",
  "Gspr": " win32k.sys                           - GDITAG_SPRITESCAN\r\n",
  "IpSC": " ipsec.sys    -  send complete context\r\n",
  "IpSA": " ipsec.sys    -  security associations (SA)\r\n",
  "CcWK": " nt!cc        - Kernel Cache Manager lookaside list\r\n",
  "DClm": " win32kbase!DirectComposition::CAnimationLoggingManager::_allocate                        - DCOMPOSITIONTAG_ANIMATIONLOGGINGMANAGERMARSHALER\r\n",
  "Umsr": " win32kfull!NtUserRequestMoveSizeOperation - USERTAG_MOVESIZE_REQUEST_PARAMS\r\n",
  "RcpS": " sacdrv.sys -     Security related block\r\n",
  "IpSI": " ipsec.sys    -  initial allocations\r\n",
  "MSst": " refs.sys     - Minstore stream object\r\n",
  "NDAe": " ndis.sys     - NDIS_PD_EC\r\n",
  "8042": " i8042prt.sys - PS/2 keyboard and mouse\r\n",
  "NDAf": " ndis.sys     - NDIS_PD_FILTER\r\n",
  "Kse9": " ksecdd.sys   - Security driver allocs for sec package 9\r\n",
  "Kse8": " ksecdd.sys   - Security driver allocs for sec package 8\r\n",
  "NDAc": " ndis.sys     - NDIS_PD_CLIENT\r\n",
  "NDAb": " ndis.sys     - NDIS_PD_BLOCK\r\n",
  "Kse5": " ksecdd.sys   - Security driver allocs for sec package 5\r\n",
  "Kse4": " ksecdd.sys   - Security driver allocs for sec package 4\r\n",
  "Kse7": " ksecdd.sys   - Security driver allocs for sec package 7\r\n",
  "Kse6": " ksecdd.sys   - Security driver allocs for sec package 6\r\n",
  "Kse1": " ksecdd.sys   - Security driver allocs for sec package 1\r\n",
  "Kse0": " ksecdd.sys   - Security driver allocs for sec package 0\r\n",
  "fpxp": " wof.sys      - Compressed file xpress context\r\n",
  "Kse2": " ksecdd.sys   - Security driver allocs for sec package 2\r\n",
  "CSnt": " <unknown>    - Cluster Network driver\r\n",
  "NDAt": " ndis.sys     - NDIS_PD_QUEUE_TRACKER\r\n",
  "VWnd": " vwififlt.sys -  Virtual Wi-Fi Filter Driver (requests)\r\n",
  "Ipap": " tcpip.sys    - IPsec pend context\r\n",
  "Rcp?": " sacdrv.sys - SAC Driver (Headless)\r\n",
  "Ipas": " tcpip.sys    - IP Buffers for Address Sort\r\n",
  "NpFD": " npfs.sys     - DCB, directory block\r\n",
  "GVms": " win32k!MulSaveScreenBits             - GDITAG_MULTISAVEBITS\r\n",
  "NpFC": " npfs.sys     - ROOT_DCB CCB\r\n",
  "Gsp ": " win32k!pSpCreateSprite               - GDITAG_SPRITE\r\n",
  "NpFw": " npfs.sys     - Write block\r\n",
  "NpFq": " npfs.sys     - Query template buffer used for directory query\r\n",
  "NpFr": " npfs.sys     - DATA_ENTRY records (read/write buffers)\r\n",
  "NpFs": " npfs.sys     - Client security context\r\n",
  "KSdc": " <unknown>    -    default clock\r\n",
  "NpFn": " npfs.sys     - Name block\r\n",
  "KSda": " <unknown>    -    default allocator\r\n",
  "NpFi": " npfs.sys     - NPFS client info buffer.\r\n",
  "KSdh": " <unknown>    -    device header\r\n",
  "NpFg": " npfs.sys     - Global storage\r\n",
  "MuDn": " mup.sys      - Device name\r\n",
  "TpWc": " nt!ex        - Threadpool minipacket context\r\n",
  "NpFc": " npfs.sys     - CCB, client control block\r\n",
  "Vi40": " dxgmms2.sys  - Video memory manager migration table lock\r\n",
  "Dacl": " <unknown>    - Temp allocations for object DACLs\r\n",
  "Mmdi": " nt!mm        - MDLs for physical memory allocations\r\n",
  "wprt": " wof.sys      - Wim resource table\r\n",
  "Gpbm": " win32k.sys                           - GDITAG_POOL_BITMAP_BITS\r\n",
  "VdWd": " Vid.sys - Virtual Machine Virtualization Infrastructure Driver (WDF)\r\n",
  "Gdev": " win32k.sys                           - GDITAG_DEVMODE\r\n",
  "fpdw": " wof.sys      - Compressed file decompression workspace\r\n",
  "VM??": " volmgr.sys   - Volume Manager\r\n",
  "IpEQ": " ipsec.sys    -  event queue\r\n",
  "IpET": " ipsec.sys    -  ESP headers in transport mode\r\n",
  "IpEU": " ipsec.sys    -  ESP headers in tunnel mode\r\n",
  "DEvc": " devolume.sys - Drive extender volume chunk: DEVolume!VolumeChunk\r\n",
  "Cdio": " cdfs.sys     - CDFS Io context for async reads\r\n",
  "Cdil": " cdfs.sys     - CDFS Irp Context lite\r\n",
  "DEvg": " devolume.sys - Drive extender volume globals: DEVolume!DEVolumeGlobals\r\n",
  "VsAT": " vmswitch.sys - Virtual Machine Network Switch Driver (address table)\r\n",
  "Usmx": " win32k!InitializeMonitorDpiRectsAndTransforms - USERTAG_MATRIX\r\n",
  "DEvh": " devolume.sys - Drive extender volume device globals: DEVolume!DEVolumeDeviceGlobals\r\n",
  "DEvo": " devolume.sys - Drive extender volume message: DEVolume!DEVolume\r\n",
  "Cdic": " cdfs.sys     - CDFS Irp Context\r\n",
  "DEvm": " devolume.sys - Drive extender volume message: DEVolume!DE_VOLUME_MESSAGE\r\n",
  "CcVa": " nt!cc        - Cache Manager Initial array of Vacbs\r\n",
  "DEvs": " devolume.sys - Drive extender disk set volume: DEVolume!DiskSetVolume\r\n",
  "UlDB": " http.sys     - Debug\r\n",
  "Sm??": " mrxsmb.sys    - SMB miniredirector allocations\r\n",
  "POWI": " nt!po        - Power Work Item (executive worker thread work item entry)\r\n",
  "Usmi": " win32k!MirrorRegion                  - USERTAG_MIRROR\r\n",
  "NBqh": " <unknown>    -     Non-blocking queue entries used to carry the real data in the queue.\r\n",
  "Bat?": " <unknown>    - Battery Class drivers\r\n",
  "ScUn": " <unknown>    - Default Tag for pnp class driver allocations\r\n",
  "Stac": " <unknown>    - Stack Trace Database - i386 checked and built with NTNOFPO=1 only\r\n",
  "BatC": " <unknown>    -     Composite battery driver\r\n",
  "RaDA": " tcpip.sys    - Raw Socket Discretionary ACLs\r\n",
  "FMfr": " fltmgr.sys   -       FLT_FRAME structure\r\n",
  "BatM": " <unknown>    -     Control method battery driver\r\n",
  "SeAp": " nt!se        - Security Audit Parameter Record\r\n",
  "MCAM": " <unknown>    - WDM mini driver for Intel USB camera\r\n",
  "FMfz": " fltmgr.sys   -       FILE_LIST_CTRL structure\r\n",
  "SeAk": " nt!se        - Security Account Name\r\n",
  "SeAi": " nt!se        - Security Audit Work Item\r\n",
  "Ucre": " http.sys     - Receive Response\r\n",
  "BatS": " <unknown>    -     Smart battery driver\r\n",
  "Bmfd": " win32k.sys                           - GDITAG_BMP_FONT\r\n",
  "FMfc": " fltmgr.sys   -       FLTMGR_FILE_OBJECT_CONTEXT structure\r\n",
  "Time": " nt!ke        - Timer objects\r\n",
  "SeAc": " nt!se        - Security ACL\r\n",
  "FMfl": " fltmgr.sys   -       FLT_FILTER structure\r\n",
  "FMfn": " fltmgr.sys   -       NAME_CACHE_NODE structure\r\n",
  "FMfi": " fltmgr.sys   -       Fast IO dispatch table\r\n",
  "FMfk": " fltmgr.sys   -       Byte Range Lock structure\r\n",
  "Ussa": " win32k!xxxBroadcastMessage           - USERTAG_SMS_ASYNC\r\n",
  "RaDf": " storport.sys - RaidInitializeDeferredQueue storport!_RAID_DEFERRED_QUEUE.FreeList\r\n",
  "Ussc": " win32k!xxxInterSendMsgEx             - USERTAG_SMS_CAPTURE\r\n",
  "QuU2": " mpsdrv.sys   - MPSDRV upcall response\r\n",
  "Usse": " win32k!SetDisconnectDesktopSecurity  - USERTAG_SECURITY\r\n",
  "AlP5": " tcpip.sys    -     ALE 5-tuple state\r\n",
  "EQSy": " tcpip.sys    - EQoS proxy data\r\n",
  "EQSx": " tcpip.sys    - EQoS security object\r\n",
  "Ussi": " win32k!NtUserSendInput               - USERTAG_SENDINPUT\r\n",
  "VssM": " vmswitch.sys - Virtual Machine Network Switch Driver (miniport NIC)\r\n",
  "EQSt": " tcpip.sys    - EQoS policy trim scratch\r\n",
  "Ussm": " win32k!InitSMSLookaside              - USERTAG_SMS\r\n",
  "smWi": " nt!store or rdyboost.sys - ReadyBoost various work items\r\n",
  "EQSp": " tcpip.sys    - EQoS generic policy data\r\n",
  "smAc": " nt!store     -         ReadyBoost device arrival context\r\n",
  "IIts": " <unknown>    - Transfer Context\r\n",
  "DVFn": " <unknown>    - FileName, DAV MiniRedir\r\n",
  "Batt": " <unknown>    -     Battery class driver\r\n",
  "VssP": " vmswitch.sys - Virtual Machine Network Switch Driver (protocol NIC)\r\n",
  "DVFi": " <unknown>    - FileInfo, DAV MiniRedir\r\n",
  "Ussw": " win32k!xxxDesktopRecalc              - USERTAG_ADR\r\n",
  "DCvb": " win32kbase!DirectComposition::CViewBoxMarshaler::_allocate                               - DCOMPOSITIONTAG_VIEWBOXMARSHALER\r\n",
  "Ussy": " win32k!xxxDesktopThread              - USERTAG_SYSTEM\r\n",
  "Ussx": " win32k!SetWindowExtendedBoundsMargin - USERTAG_UPDATEFRAMEMARGINS\r\n",
  "EQSe": " tcpip.sys    - EQoS QIM endpoint\r\n",
  "FsVg": " fsvga.sys    - International VGA support\r\n",
  "FlmC": " tcpip.sys    - Framing Layer Client Contexts\r\n",
  "IU??": " <unknown>    - IIS Utility Driver\r\n",
  "SrMP": " sr.sys       -         Mount point information\r\n",
  "FlmP": " tcpip.sys    - Framing Layer Provider Contexts\r\n",
  "RB??": " <unknown>    - RedBook Filter Driver, static allocations\r\n",
  "ScC7": " classpnp.sys -  Sense info buffer\r\n",
  "ScC6": " classpnp.sys -  START_UNIT completion context\r\n",
  "PcDi": " <unknown>    - WDM audio stuff\r\n",
  "ScC8": " classpnp.sys -  Registry value name\r\n",
  "ScC?": " cdrom.sys    -  CdRom\r\n",
  "PcDm": " <unknown>    - DirectMusic MXF objects (WDM audio)\r\n",
  "II??": " <unknown>    - IP in IP tunneling\r\n",
  "PnpX": " nt!pnp       - PNPMGR DevQuery\r\n",
  "PnpY": " nt!pnp       - PNPMGR usermode device notifications\r\n",
  "Glid": " win32k!GetLanguageID                 - GDITAG_LOCALEINFO\r\n",
  "PnpR": " nt!pnp       - PNPMGR memory bitmap\r\n",
  "PnpS": " nt!pnp       - PNPMGR dependent info\r\n",
  "PnpP": " nt!pnp       - PNPMGR veto device object\r\n",
  "PnpQ": " nt!pnp       - PNPMGR partition resource list\r\n",
  "PnpV": " nt!pnp       - PNPMGR notify entry loc\r\n",
  "PnpW": " nt!pnp       - PNPMGR SwDevice\r\n",
  "PnpT": " nt!pnp       - PNPMGR provider info\r\n",
  "PnpU": " nt!pnp       - PNPMGR async set status control\r\n",
  "PnpJ": " nt!pnp       - PNPMGR device event list\r\n",
  "PnpK": " nt!pnp       - PNPMGR device event entry\r\n",
  "PnpH": " nt!pnp       - PNPMGR service name\r\n",
  "PnpI": " nt!pnp       - PNPMGR instance path\r\n",
  "PnpN": " nt!pnp       - PNPMGR PDO array\r\n",
  "PnpO": " nt!pnp       - PNPMGR veto process\r\n",
  "PnpL": " nt!pnp       - PNPMGR device event workitem\r\n",
  "PnpM": " nt!pnp       - PNPMGR veto buffer\r\n",
  "PnpC": " nt!pnp       - PNPMGR target device notify\r\n",
  "Uspb": " win32k!fnPOWERBROADCAST              - USERTAG_POWERBROADCAST\r\n",
  "PnpA": " nt!pnp       - PNPMGR PnpRtl Operations\r\n",
  "PnpF": " nt!pnp       - PNPMGR eject data\r\n",
  "PnpG": " nt!pnp       - PNPMGR generic\r\n",
  "PsRl": " nt!ps        - Captured memory reserve list (temporary allocation)\r\n",
  "ScCc": " cdrom.sys    -      Context of completion routine\r\n",
  "Pnp8": " nt!pnp       - PNPMGR async target device change notify\r\n",
  "Pnp9": " nt!pnp       - PNPMGR HW profile notify\r\n",
  "NEOD": " newt_ndis6.sys - NEWT OID\r\n",
  "ScCd": " cdrom.sys    -      Disc information\r\n",
  "Pnp2": " nt!pnp       - PNPMGR device action request\r\n",
  "ohci": " <unknown>    - 1394 OHCI host controller driver\r\n",
  "Pnp0": " nt!pnp       - PNPMGR rebalance resource request table\r\n",
  "Pnp1": " nt!pnp       - PNPMGR IRP completion context\r\n",
  "Pnp6": " nt!pnp       - PNPMGR resource request\r\n",
  "Pnp7": " nt!pnp       - PNPMGR deferred notify entry\r\n",
  "Pnp4": " nt!pnp       - PNPMGR CM API\r\n",
  "Pnp5": " nt!pnp       - PNPMGR assign resources context\r\n",
  "Itri": " tcpip.sys    - IPsec inbound packet security context\r\n",
  "AlDN": " tcpip.sys    -     ALE endpoint delete notify\r\n",
  "ScCp": " cdrom.sys    -      Play active checks\r\n",
  "KDNr": " kdnic.sys    - Network Kernel Debug Adapter RECV-NBL\r\n",
  "Itro": " tcpip.sys    - IPsec outbound session security context\r\n",
  "Cdgs": " cdfs.sys     - CDFS Generated short name\r\n",
  "Qprz": " <unknown>    -      Rhizome\r\n",
  "TOBJ": " rdpdr.sys - Topology object\r\n",
  "ScCC": " cdrom.sys    -      Ioctl GET_CONFIGURATION\r\n",
  "KDNF": " kdnic.sys    - Network Kernel Debug Adapter FRAME\r\n",
  "ScCA": " cdrom.sys    -      Autorun disable functionality\r\n",
  "ScCG": " cdrom.sys    -      GESN buffer\r\n",
  "ScCF": " cdrom.sys    -      Feature descriptor\r\n",
  "ScCD": " cdrom.sys    -      Adaptor & Device descriptor buffer\r\n",
  "VmUe": " volmgrx.sys  - User entries\r\n",
  "ScCI": " cdrom.sys    -      Sense info buffers\r\n",
  "FDUm": " win32k.sys                           - GDITAG_UMFD_UM_BUFFER\r\n",
  "ScCM": " cdrom.sys    -      Mode data buffer\r\n",
  "FMpl": " fltmgr.sys   -       Cache aware pushLock\r\n",
  "ScCS": " cdrom.sys    -      Srb allocation\r\n",
  "FMpr": " fltmgr.sys   -       FLT_PRCB structure\r\n",
  "SeSc": " nt!se        - Captured Security Descriptor\r\n",
  "KDNT": " kdnic.sys    - Network Kernel Debug Adapter TCB\r\n",
  "KDNR": " kdnic.sys    - Network Kernel Debug Adapter RCB\r\n",
  "ScCU": " cdrom.sys    -      Update capacity path\r\n",
  "Gh?5": " win32k.sys                           - GDITAG_HMGR_SURF_TYPE\r\n",
  "KDN_": " kdnic.sys    - Network Kernel Debug Adapter\r\n",
  "StCc": " netio.sys    - WFP stream inspection call context\r\n",
  "ScCX": " cdrom.sys    -      Security descriptor\r\n",
  "fpRD": " wof.sys      - Compressed file large read buffer\r\n",
  "Mmpp": " nt!mm        - Mm prototype PTEs for pool\r\n",
  "TDIg": " <unknown>    - TDI resource\r\n",
  "TDIf": " <unknown>    - TDI resource\r\n",
  "TDIe": " <unknown>    - TDI resource\r\n",
  "TDId": " <unknown>    - TDI resource\r\n",
  "TDIc": " <unknown>    - TDI resource\r\n",
  "Lrbb": " <unknown>    -     Write behind buffer\r\n",
  "Cryp": " ksecdd.sys   - Crypto allocations\r\n",
  "TDIk": " <unknown>    - TDI resource\r\n",
  "TDIv": " <unknown>    - TDI resource\r\n",
  "TDIu": " <unknown>    - TDI resource\r\n",
  "TTFC": " win32k.sys                           - GDITAG_TT_FONT_CACHE\r\n",
  "Gsty": " win32k!GreExtCreatePen               - GDITAG_PENSTYLE\r\n",
  "Udfd": " udfs.sys     - Udfs file Scb\r\n",
  "SdCc": " <unknown>    - ObsSecurityDescriptorCache / SECURITY_DESCRIPTOR_CACHE_ENTRIES\r\n",
  "Udff": " udfs.sys     - Udfs Fcb\r\n",
  "PsQb": " nt!ps        - Process quota block\r\n",
  "Udfi": " udfs.sys     - Udfs directory Scb\r\n",
  "Wait": " nt!io        - WaitCompletion Packets\r\n",
  "LSwr": " srv.sys      -     SMB1 raw work context\r\n",
  "LSws": " srv.sys      -     SMB1 BlockTypeWorkContextSpecial\r\n",
  "LSwq": " srv.sys      -     SMB1 BlockTypeWorkQueue\r\n",
  "Gsta": " win32k.sys                           - GDITAG_STACKTRACE\r\n",
  "RxSc": " rdbss.sys - RDBSS SrvCall\r\n",
  "Asy2": " <unknown>    - ndis / ASYNC_INFO_TAG\r\n",
  "MmLa": " nt!mm        - Memory list locks\r\n",
  "NDbi": " ndis.sys     - NDIS_TAG_BUS_INTERFACE\r\n",
  "MmLd": " nt!mm        - Mm load module database\r\n",
  "IsRc": " tcpip.sys    - IPsec rebalance context\r\n",
  "LSwi": " srv.sys      -     SMB1 initial work context\r\n",
  "IBm*": " wibms.sys - Windows Infiniband Management Server pool tags\r\n",
  "MmLl": " nt!mm        - Large page memory run allocation for finding large pages\r\n",
  "RfCB": " rfcomm.sys   -   RCOMMM\r\n",
  "VHrc": " vmusbhub.sys - Virtual Machine USB Hub Driver (request context)\r\n",
  "VNCW": " netvsc50.sys/netvsc60.sys - Virtual Machine Network VSC Driver (WDF)\r\n",
  "InNP": " tcpip.sys    - Inet Nsi Providers\r\n",
  "Sc??": " <unknown>    - Mass storage driver tags\r\n",
  "Flst": " <unknown>    - EXIFS Freelist\r\n",
  "Lrlb": " <unknown>    -     Lock Control Block buffers\r\n",
  "Lrlc": " <unknown>    -     Lock Control Blocks\r\n",
  "RtPi": " <unknown>    - Temp allocation for product type key\r\n",
  "Galp": " win32k!AlphaScanLineBlend            - GDITAG_ALPHABLEND\r\n",
  "ArpS": " <unknown>    -     AtmArpS SAP structure\r\n",
  "Adnc": " tcpip.sys    -     ALE endpoint deactivation notification context\r\n",
  "Gmso": " win32k!MULTISORTBLTORDER::MULTISORTBLTORDER - GDITAG_DISPURF_SORT\r\n",
  "RKRW": " mpsdrv.sys   - MPSDRV work item\r\n",
  "ImPl": " ndisimplatform.sys - NDIS IM (LBFO) Platform\r\n",
  "SVXD": " synvidxd.dll    - WDDM Synthetic Video Display Driver\r\n",
  "UspC": " win32k!AssignPointerCaptureData      - USERTAG_POINTERCAPTUREDATA\r\n",
  "CcFn": " nt!cc        - Cache Manager File name for popups\r\n",
  "Thrm": " <unknown>    - Thermal zone structure\r\n",
  "KeIC": " <unknown>    - Kernel Interrupt Object Chain\r\n",
  "RBRg": " <unknown>    - RedBook - driverExtension->RegistryPath\r\n",
  "Thre": " nt!ps        - Thread objects\r\n",
  "Tnbt": " <unknown>    - NB Pool\r\n",
  "Ovfl": " <unknown>    - The internal pool tag table has overflowed - usually this is a result of nontagged allocations being made\r\n",
  "VVpp": " vhdparser.sys - Virtual Machine Storage VHD Parser Driver (parser)\r\n",
  "ObDm": " nt!ob        - object device map\r\n",
  "Abrc": " tcpip.sys    -     ALE bind request inspection context\r\n",
  "MSb+": " refs.sys     - Minstor B+ table\r\n",
  "ObDi": " nt!ob        - object directory\r\n",
  "SeRO": " nt!se        - Learning Mode Root Object\r\n",
  "NV  ": " <unknown>      - nVidia video driver\r\n",
  "SWii": " <unknown>    -         instance ID\r\n",
  "Abrl": " tcpip.sys    -     ALE bind redirect layer data\r\n",
  "Vi5e": " dxgmms2.sys  - Video memory manager scheduling log\r\n",
  "p2de": " perm2dll.dll - Permedia2 display driver - debug.c\r\n",
  "KSew": " <unknown>    -    oneshot event deletion workitem\r\n",
  "NlsK": " nt!ex        - Nls data\r\n",
  "KSep": " <unknown>    -    irp system buffer event parameter\r\n",
  "KSer": " <unknown>    -    QM error report\r\n",
  "p2ds": " perm2dll.dll - Permedia2 display driver - d3dstate.c\r\n",
  "sbp2": " <unknown>    - Sbp2 1394 storage port driver\r\n",
  "p2dt": " perm2dll.dll - Permedia2 display driver - d3dtxman.c\r\n",
  "KSee": " <unknown>    -    event entry\r\n",
  "KSed": " <unknown>    -    oneshot event deletion dpc\r\n",
  "DCro": " win32kbase!DirectComposition::CRotateTransformMarshaler::_allocate                       - DCOMPOSITIONTAG_ROTATETRANSFORMMARSHALER\r\n",
  "DrEx": " rdpdr.sys    - Exchange object\r\n",
  "Nls ": " <unknown>    - Nls strings\r\n",
  "TcTW": " tcpip.sys    - TCP Time Wait TCBs\r\n",
  "IPrq": " tcpip.sys    - IP Request Control data\r\n",
  "Tcpt": " tcpip.sys    - TCP Timers\r\n",
  "GUma": " win32k!GDIEngUserMemAllocNodeAlloc   - GDITAG_ENG_USER_MEM_ALLOC_TABLE\r\n",
  "Atk ": " <unknown>    - Appletalk transport\r\n",
  "ObZn": " nt!ob        - object zone\r\n",
  "NDPX": " ndis.sys     -     NDIS Proxy allocations\r\n",
  "Used": " win32k!AddOrUpdateListener           - USERTAG_EDGY\r\n",
  "UsPM": " win32k!InitPostMortemLogging         - USERTAG_POSTMORTEM_LOGGING\r\n",
  "Gsth": " win32k.sys                           - GDITAG_STRETCHBLT\r\n",
  "KsFI": " <unknown>    -    filter instance\r\n",
  "SWdn": " <unknown>    -         device name\r\n",
  "NDPi": " ndis.sys     - NWLNKIPX\r\n",
  "NDPn": " ndis.sys     - NWLNKNB\r\n",
  "NDPb": " ndis.sys     - NBF\r\n",
  "Ipnc": " tcpip.sys    - IPsec negotiation context\r\n",
  "LSac": " srv.sys      -     SMB1 BlockTypeAdminCheck\r\n",
  "IPro": " tcpip.sys    - IP Router Context\r\n",
  "Ipng": " tcpip.sys    - IP Generic buffers (Address, Interface, Packetize, Route allocations)\r\n",
  "SWda": " <unknown>    -         POOLTAG_DEVICE_ASSOCIATION\r\n",
  "p2d3": " perm2dll.dll - Permedia2 display driver - d3d.c\r\n",
  "p2d6": " perm2dll.dll - Permedia2 display driver - d3ddx6.c\r\n",
  "NDPs": " ndis.sys     - NWLNKSPX\r\n",
  "NDPp": " ndis.sys     - Packet Scheduler.\r\n",
  "LSas": " srv.sys      -     SMB1 BlockTypeAdapterStatus\r\n",
  "SWdr": " <unknown>    -         POOLTAG_DEVICE_DRIVER_REGISTRY\r\n",
  "NDPw": " ndis.sys     - WAN_PACKET_TAG\r\n",
  "NDPt": " ndis.sys     - TCPIP\r\n",
  "MmZw": " nt!mm        - Work items for zeroing pages and pagefiles\r\n",
  "Even": " <unknown>    - Event objects\r\n",
  "Evel": " <unknown>    - EFS file system filter driver lookaside list\r\n",
  "FMas": " fltmgr.sys   -       ASYNC_IO_COMPLETION_CONTEXT structure\r\n",
  "smBX": " rdyboost.sys -         ReadyBoot boot plan decompression workspace buffer\r\n",
  "Mn0D": " monitor.sys  - Cached supported monitor frequency ranges WMI data block (from E-EDID v.1.x base block)\r\n",
  "smBR": " rdyboost.sys -         ReadyBoost volume ranges array\r\n",
  "smBP": " rdyboost.sys -         ReadyBoot boot plan buffer\r\n",
  "Txrn": " ntfs.sys     - TXF_NONPAGED_RMCB\r\n",
  "RDPD": " rdpdr.sys - Device list object\r\n",
  "FMac": " fltmgr.sys   -       ASCII String buffers\r\n",
  "LpcM": " <unknown>    - Local procedure call message blocks\r\n",
  "smBD": " rdyboost.sys -         ReadyBoot decompressed boot plan buffer\r\n",
  "CBSI": " cbsi.sys     - Common Block Store\r\n",
  "SW??": " <unknown>    - Software Bus Enumerator\r\n",
  "SDa ": " smbdirect.sys - SMB Direct socket objects\r\n",
  "EQPs": " tcpip.sys    - EQoS policy scratch data\r\n",
  "EQPp": " tcpip.sys    - EQoS policy profile entry\r\n",
  "Senm": " <unknown>    - Serenum (RS-232 serial bus enumerator)\r\n",
  "smBr": " rdyboost.sys -         ReadyBoost volume range\r\n",
  "SVXM": " synvidxm.sys    - WDDM Synthetic Video Miniport Driver\r\n",
  "EQPt": " tcpip.sys    - EQoS policy table\r\n",
  "UsTI": " win32k!NtUserQueryInformationThread  - USERTAG_THREADINFORMATION\r\n",
  "SWrs": " <unknown>    -         reference string\r\n",
  "SCB3": " <unknown>    -  Bull SmarTlp PnP\r\n",
  "Dati": " <unknown>    - ati video driver\r\n",
  "wpwi": " wof.sys      - Wim work item\r\n",
  "MScp": " refs.sys     - Minstore cached pin\r\n",
  "wpwf": " wof.sys      - Wim file\r\n",
  "Bu* ": " <unknown>    - burneng.sys from adaptec\r\n",
  "fpwi": " wof.sys      - Compressed file work item\r\n",
  "User": " win32k!InitCreateUserCrit            - USERTAG_ERESOURCE\r\n",
  "KSsi": " <unknown>    -    software bus interface\r\n",
  "KSsh": " <unknown>    -    stream headers\r\n",
  "IoRi": " nt!io        - I/O SubSystem Driver Reinitialization Callback Packet\r\n",
  "KSsc": " <unknown>    -    port driver stream FsContext\r\n",
  "Devi": " <unknown>    - Device objects\r\n",
  "IoRb": " nt!io        - Io remote boot related\r\n",
  "KSsf": " <unknown>    -    set information file buffer\r\n",
  "Gffv": " win32k.sys                           - GDITAG_FONTFILEVIEW\r\n",
  "DW32": " <unknown>    - W32 video driver\r\n",
  "DEga": " devolume.sys - Drive extender guild array\r\n",
  "WmDS": " <unknown>    - Wmi DataSource chunks\r\n",
  "PlRB": " storport.sys - PortAllocateRegistryBuffer storport!_PORT_REGISTRY_INFO.Buffer\r\n",
  "DChr": " win32kbase!DirectComposition::CSharedReadHolographicInteropTextureMarshaler::_allocate   - DCOMPOSITIONTAG_SHAREDREADHOLOGRAPHICINTEROPTEXTUREMARSHALER\r\n",
  "MuSr": " mup.sys      - Surrogate IRP info\r\n",
  "KSsp": " <unknown>    -    serialized property set\r\n",
  "IoRN": " nt!io        - Registry key name (temp allocation)\r\n",
  "MSci": " refs.sys     - Minstore metadata cache instance\r\n",
  "DChp": " win32kbase!DirectComposition::CHoverPointerSourceMarshaler::_allocate                    - DCOMPOSITIONTAG_HOVERPOINTERSOURCEMARSHALER\r\n",
  "FIPc": " fileinfo.sys - FileInfo FS-filter Prefetch Context\r\n",
  "VMIN": " vwifimp.sys     - Virtual Wi-Fi miniport\r\n",
  "MSch": " refs.sys     - Minstore read cache hash table\r\n",
  "Uqcm": " win32kmin!AllocQEntry - USERTAG_QMSG_COREMSGK_INFO\r\n",
  "UsId": " win32k!NSInstrumentation::CSharedStorage::InitializeCommon   - USERTAG_SHARED_STORAGE\r\n",
  "LBid": " <unknown>    -     Illegal datagram context\r\n",
  "LBic": " <unknown>    -     IRP context\r\n",
  "Ucal": " win32k!DriverEntry                   - USERTAG_SERVICE_TABLE\r\n",
  "Ucac": " http.sys     - Auth Cache Pool\r\n",
  "MScm": " refs.sys     - Minstore composite\r\n",
  "DCht": " win32kbase!DirectComposition::CHwndTargetMarshaler::_allocate                            - DCOMPOSITIONTAG_HWNDTARGETMARSHALER\r\n",
  "MScl": " refs.sys     - Minstore read cache line\r\n",
  "Usol": " win32kbase!InputTraceLogging::PerfRegion::Initialize - USERTAG_PERFREGION_LOOKASIDE\r\n",
  "Gdd ": " <unknown>    -     Gdi ddraw PKEY_VALUE_FULL_INFORMATION\r\n",
  "Cdfd": " cdfs.sys     - CDFS Data Fcb\r\n",
  "HalV": " ntoskrnl.exe - Driver Verifier DMA checking\r\n",
  "Cdfn": " cdfs.sys     - CDFS Nonpaged Fcb\r\n",
  "Nb07": " netbt.sys    - NetBT datagram request tracker\r\n",
  "Cdfl": " cdfs.sys     - CDFS Filelock\r\n",
  "SmTp": " mrxsmb.sys    - SMB transport\r\n",
  "Cdfi": " cdfs.sys     - CDFS Index Fcb\r\n",
  "CTE ": " <unknown>    - Common transport environment (ntos\\inc\\cxport.h, used by tdi)\r\n",
  "Cdft": " cdfs.sys     - CDFS Fcb Table entry\r\n",
  "Cdfs": " cdfs.sys     - CDFS General Allocation\r\n",
  "SmTd": " mrxsmb.sys    - SMB TDI notify\r\n",
  "VuCU": " vuc.sys       - Virtual Machine USB Connector Driver (connector URB)\r\n",
  "DCc2": " win32kbase!DirectComposition::CComponentTransform2DMarshaler::_allocate                  - DCOMPOSITIONTAG_COMPONENTTRANSFORM2DMARSHALER\r\n",
  "MScc": " refs.sys     - Minstore tx checksum context\r\n",
  "NBFw": " <unknown>    - NBF work item\r\n",
  "Gkbm": " win32k.sys                           - GDITAG_KMODE_BITMAP\r\n",
  "FMsl": " fltmgr.sys   -       STREAM_LIST_CTRL structure\r\n",
  "FCcr": " dxgkrnl!CContentResource::Create - FLIPCONTENT_CONTENTRESOURCE\r\n",
  "VidL": " videoprt.sys - VideoPort Allocation List (FDO_EXTENSION)\r\n",
  "FMsd": " fltmgr.sys   -       Security descriptors\r\n",
  "VmTc": " volmgrx.sys  - Table of contents\r\n",
  "FMsc": " fltmgr.sys   -       SECTION_CONTEXT structure\r\n",
  "VmTa": " volmgrx.sys  - I/O tasks\r\n",
  "MScd": " refs.sys     - Minstore read cache dirty page array\r\n",
  "WfSt": " <unknown>    - WFP string\r\n",
  "Vi42": " dxgmms2.sys  - Video memory manager global alloc nonpaged\r\n",
  "rbIr": " <unknown>    - RedBook - Irp for read/stream\r\n",
  "Vpb ": " <unknown>    - Io, vpb's\r\n",
  "BTSR": " bthser.sys   - Bluetooth serial minidriver\r\n",
  "NBFt": " <unknown>    - NBF connection table\r\n",
  "Gdda": " <unknown>    -     Gdi ddraw attach list\r\n",
  "DCco": " win32kbase!DirectComposition::CComponentTransform3DMarshaler::_allocate                  - DCOMPOSITIONTAG_COMPONENTTRANSFORM3DMARSHALER\r\n",
  "DCcl": " win32kbase!DirectComposition::CCompositionLight::_allocate                               - DCOMPOSITIONTAG_LIGHTMARSHALER\r\n",
  "ExWl": " <unknown>    - Executive worker list entry\r\n",
  "Gdde": " <unknown>    -     Gdi ddraw event\r\n",
  "File": " <unknown>    - File objects\r\n",
  "INTC": " <unknown>    - Intel video driver\r\n",
  "Gddf": " <unknown>    -     Gdi ddraw driver heaps\r\n",
  "KSAI": " <unknown>    -    allocator instance\r\n",
  "DCcg": " win32kbase!DirectComposition::CClipGroupMarshaler::_allocate                             - DCOMPOSITIONTAG_CLIPGROUPMARSHALER\r\n",
  "DCcb": " win32kbase!DirectComposition::CCompositionSurfaceBitmapMarshaler::_allocate              - DCOMPOSITIONTAG_HCOMPBITMAPMARSHALER\r\n",
  "DCcc": " win32kbase!DirectComposition::CConnection::_allocate                                     - DCOMPOSITIONTAG_CONNECTION\r\n",
  "ATdi": " AppTag cliendata index buffer\r\n",
  "DCca": " win32kbase!DirectComposition::CConditionalExpressionMarshaler::_allocate                 - DCOMPOSITIONTAG_CONDITIONALEXPRESSIONMARSHALER\r\n",
  "NLbd": " tcpip.sys    - Network Layer Buffer Data\r\n",
  "Gddp": " <unknown>    -     Gdi ddraw driver caps\r\n",
  "ATdt": " AppTag cliendata temp buffer\r\n",
  "smLb": " nt!store     -         ReadyBoost virtual store manager log buffer\r\n",
  "Gddv": " <unknown>    -     Gdi ddraw driver video memory list\r\n",
  "DCcv": " win32kbase!DirectComposition::CrossChannelVisualData::_allocate                          - DCOMPOSITIONTAG_CROSSCHANNELVISUALDATA\r\n",
  "DCcw": " win32kbase!DirectComposition::CScreenCursorMarshaler::_allocate                          - DCOMPOSITIONTAG_SCREENCURSORMARSHALER\r\n",
  "Gpat": " win32k.sys                           - GDITAG_PATHOBJ\r\n",
  "DCcu": " win32kbase!DirectComposition::CSharedReadCaptureControllerMarshaler::_allocate           - DCOMPOSITIONTAG_READCAPTURECONTROLLERMARSHALER\r\n",
  "DCcr": " win32kbase!DirectComposition::CCaptureRenderTargetMarshaler::_allocate                   - DCOMPOSITIONTAG_CAPTURERENDERTARGETMARSHALER\r\n",
  "DCcs": " win32kbase!DirectComposition::CCriticalSection::_allocate                                - DCOMPOSITIONTAG_CRITICALSECTION\r\n",
  "Hmgo": " hcaport.sys - HCAPORT_TAG_WQ_MG_INFO\r\n",
  "DCcq": " win32kbase!DirectComposition::CCaptureControllerMarshaler::_allocate                     - DCOMPOSITIONTAG_CAPTURECONTROLLERMARSHALER\r\n",
  "ScRp": " <unknown>    -      Partition entry\r\n",
  "Uscu": " win32k!_CreateEmptyCursorObject      - USERTAG_CURSOR\r\n",
  "ScRr": " <unknown>    -      Remove lock\r\n",
  "Usny": " win32k!CreateNotify                  - USERTAG_NOTIFY\r\n",
  "ScRt": " <unknown>    -      Table entry\r\n",
  "GddD": " <unknown>    -     Gdi ddraw dummy page\r\n",
  "ScRv": " <unknown>    -      Dependant volume relations lists\r\n",
  "ScRw": " <unknown>    -      Power mgmt private work item\r\n",
  "rbBu": " <unknown>    - RedBook - Buffer for read/stream\r\n",
  "DEub": " devolume.sys - Drive extender unaligned EccPage temp buffer: DEVolume!DeEccPage\r\n",
  "sm??": " nt!store or rdyboost.sys - ReadyBoost allocations\r\n",
  "Hal ": " hal.dll      - Hardware Abstraction Layer\r\n",
  "TMcf": " dxgkrnl!CCompositionFrame::Create                     - TOKENMANAGER_COMPOSITIONFRAME\r\n",
  "GOPM": " win32k.sys                           - GDITAG_OPM\r\n",
  "TMcb": " dxgkrnl!CCompositionToken::Initialize                 - TOKENMANAGER_COMPOSITIONTOKENBUFFER\r\n",
  "KSoh": " <unknown>    -    object header\r\n",
  "Usvl": " win32k!VWPLAdd                       - USERTAG_VWPL\r\n",
  "ScRi": " <unknown>    -      IOCTL buffer\r\n",
  "Usna": " win32k!UserPostNKAPC                 - USERTAG_NKAPC\r\n",
  "CMDa": " nt!cm        - value data cache pool tag\r\n",
  "CMDc": " nt!cm        - Configuration Manager Cache (registry)\r\n",
  "Sema": " <unknown>    - Semaphore objects\r\n",
  "ReFv": " refs.sys     -     ViewSup.c\r\n",
  "UlRS": " http.sys     - Non-Paged Resource\r\n",
  "FtS ": " <unknown>    - Fault tolerance driver\r\n",
  "NDcw": " ndis.sys     - NDIS_TAG_PCW - NDIS Performance Counters\r\n",
  "FlpS": " tcpip.sys    - Framing Layer Serialized Requests\r\n",
  "NDcs": " ndis.sys     - NDIS_TAG_NET_CFG_OPS_ID\r\n",
  "DChi": " win32kbase!DirectComposition::CHolographicInteropTextureMarshaler::_allocate             - DCOMPOSITIONTAG_HOLOGRAPHICINTEROPTEXTUREMARSHALER\r\n",
  "WlMh": " writelog.sys - Writelog marker header\r\n",
  "NDco": " ndis.sys     - NDIS_TAG_CO\r\n",
  "MmMl": " nt!mm        - physical memory range information\r\n",
  "NDcm": " ndis.sys     - NDIS_TAG_CM\r\n",
  "FlpI": " tcpip.sys    - Framing Layer Interfaces\r\n",
  "LSvi": " srv.sys      -     SMB1 BlockTypeVolumeInformation\r\n",
  "FlpL": " tcpip.sys    - Framing Layer Client Interface Contexts\r\n",
  "FlpM": " tcpip.sys    - Framing Layer Multicast Groups\r\n",
  "FlpC": " tcpip.sys    - Framing Layer Client Contexts\r\n",
  "NDca": " ndis.sys     - NDIS_TAG_NET_CFG_OPS_ACL\r\n",
  "Txvl": " ntfs.sys     - TXF_VSCB\r\n",
  "ScNo": " classpnp.sys - ClassPnP notification\r\n",
  "Lrme": " <unknown>    -     MPX table entries\r\n",
  "Hpfs": " <unknown>    - Pinball (aka Hpfs) allocations\r\n",
  "Vib0": " dxgmms2.sys  - GPU scheduler pending IFlip token\r\n",
  "DCm4": " win32kbase!DirectComposition::CSharedMatrixTransform3DMarshaler::_allocate               - DCOMPOSITIONTAG_SHAREDMATRIXTRANSFORM3DMARSHALER\r\n",
  "TMto": " dxgkrnl!CToken::Create                                - TOKENMANAGER_TOKENOBJECT\r\n",
  "Usfi": " win32k!CreatePointerDeviceInfo       - USERTAG_FEATUREIOCTL\r\n",
  "WfpF": " netio.sys    - WFP filters\r\n",
  "KMIX": " <unknown>    - Kmixer (wdm audio)\r\n",
  "RaSN": " storport.sys - RaidBusEnumeratorAllocateUnitResources storport!_BUS_ENUM_RESOURCES.SenseInfo\r\n",
  "Lrmt": " <unknown>    -     MPX table\r\n",
  "SrLC": " sr.sys       -         Logging context\r\n",
  "SrLB": " sr.sys       -         Log buffer\r\n",
  "VNCr": " netvsc50.sys/netvsc60.sys - Virtual Machine Network VSC Driver (RNDIS message context signature)\r\n",
  "Nph2": " netio.sys    - NetIO Protocol Header2 Data\r\n",
  "VsVN": " vmswitch.sys - Virtual Machine Network Switch Driver (VM NIC)\r\n",
  "SrLE": " sr.sys       -         Log entry\r\n",
  "Nph1": " netio.sys    - NetIO Protocol Header1 Data\r\n",
  "WfpC": " netio.sys    - WFP callouts\r\n",
  "SVid": " synthvid.sys    - LDDM Synthetic Video Miniport Driver\r\n",
  "Ra12": " storport.sys - RaidBusEnumeratorAllocateUnitResources storport!_BUS_ENUM_RESOURCES.DataBuffer\r\n",
  "SrLT": " sr.sys       -         Lookup blob\r\n",
  "VNCm": " netvsc50.sys/netvsc60.sys - Virtual Machine Network VSC Driver (RNDIS miniport driver library, message or object)\r\n",
  "VNCn": " netvsc50.sys/netvsc60.sys - Virtual Machine Network VSC Driver (NBL)\r\n",
  "UlID": " http.sys     - Conn ID Table\r\n",
  "PASf": " win32k.sys                           - GDITAG_PANNING_SURFACE\r\n",
  "DClg": " win32kbase!DirectComposition::CLineGeometryMarshaler::_allocate                          - DCOMPOSITIONTAG_LINEGEOMETRYMARSHALER\r\n",
  "NLpd": " tcpip.sys    - Network Layer Client Requests\r\n",
  "Ubwp": " win32kmin!CreateProp                 - USERTAG_BASE_WINDOW_PROPLIST\r\n",
  "Uiim": " win32kbase!CTouchProcessor::ForwardInputToManipulationThread - USERTAG_INPUT_INTEROP_MESSAGE\r\n",
  "DCmh": " win32kbase!DirectComposition::CMessageHandleInfo::_allocate                              - DCOMPOSITIONTAG_MESSAGEHANDLEINFO\r\n",
  "DCmi": " win32kbase!DirectComposition::CManipulationMarshaler::_allocate                          - DCOMPOSITIONTAG_MANIPULATIONMARSHALER\r\n",
  "DCmt": " win32kbase!DirectComposition::CMatrixTransformMarshaler::_allocate                       - DCOMPOSITIONTAG_MATRIXTRANSFORMMARSHALER\r\n",
  "DCmu": " win32kbase!DirectComposition::CSharedReadTransformMarshaler::_allocate                   - DCOMPOSITIONTAG_SHAREDREADTRANSFORMMARSHALER\r\n",
  "DCmv": " win32kbase!DirectComposition::CSharedMatrixTransformMarshaler::_allocate                 - DCOMPOSITIONTAG_SHAREDMATRIXTRANSFORMMARSHALER\r\n",
  "VmFP": " vfpext.sys - Virtual Filtering Platform driver\r\n",
  "AlE5": " tcpip.sys    -     ALE 5-tuple temp entry\r\n",
  "DfCs": " dfsc.sys     - DFS Client SHARENAME\r\n",
  "DfCr": " dfsc.sys     - DFS Client REFERRAL\r\n",
  "DfCq": " dfsc.sys     - DFS Client REGSTRING\r\n",
  "DfCp": " dfsc.sys     - DFS Client PATH\r\n",
  "DfCw": " dfsc.sys     - DFS Client TARGETINFO\r\n",
  "DfCv": " dfsc.sys     - DFS Client SERVERNAME\r\n",
  "DfCu": " dfsc.sys     - DFS Client USETABLE\r\n",
  "DfCt": " dfsc.sys     - DFS Client TREECONNECT\r\n",
  "DfCz": " dfsc.sys     - DFS Client DOMAINREFERRAL\r\n",
  "DfCy": " dfsc.sys     - DFS Client REMOTEENTRY\r\n",
  "DfCx": " dfsc.sys     - DFS Client CREDENTIALS\r\n",
  "MScu": " refs.sys     - Minstore cursor\r\n",
  "MScw": " refs.sys     - Minstore read cache write range\r\n",
  "DfCc": " dfsc.sys     - DFS Client CONNECTION\r\n",
  "DfCb": " dfsc.sys     - DFS Client REFCONTEXT\r\n",
  "DfCa": " dfsc.sys     - DFS Client PERUSERTABLE\r\n",
  "UdfN": " udfs.sys     - Udfs normalized full filename\r\n",
  "DfCg": " dfsc.sys     - DFS Client PREFIXCACHE\r\n",
  "DfCf": " dfsc.sys     - DFS Client FILENAME\r\n",
  "DfCe": " dfsc.sys     - DFS Client CSCEA\r\n",
  "DfCd": " dfsc.sys     - DFS Client CURRENTDC\r\n",
  "MSca": " refs.sys     - Minstore read cache object\r\n",
  "DfCj": " dfsc.sys     - DFS Client REWRITTENNAME\r\n",
  "DfCi": " dfsc.sys     - DFS Client INPUTBUFFER\r\n",
  "DfCh": " dfsc.sys     - DFS Client HASH\r\n",
  "DfCn": " dfsc.sys     - DFS Client DOMAINNAME\r\n",
  "DfCm": " dfsc.sys     - DFS Client CMCONTEXT\r\n",
  "DfCl": " dfsc.sys     - DFS Client DCLIST\r\n",
  "Iser": " tcpip.sys    - IPsec inbound sequence range\r\n",
  "GPal": " win32k.sys                           - GDITAG_PALETTE\r\n",
  "RxFc": " rdbss.sys - RDBSS FCB\r\n",
  "SQOS": " <unknown>    - Security quality of service in IO\r\n",
  "Tran": " <unknown>    - EXIFS Translate\r\n",
  "Ucwp": " win32kfull!CloneWindowPosAndArrangementAsync - USERTAG_CLONEWINDOWPOS\r\n",
  "Vbus": " vmbus.sys    - Virtual Machine Bus Driver\r\n",
  "wpdw": " wof.sys      - Wim decompression workspace\r\n",
  "TNbl": " tcpip.sys    - TCP Send NetBufferLists\r\n",
  "RSSE": " <unknown>    -      Security info\r\n",
  "RxFx": " rdbss.sys - RDBSS fobx\r\n",
  "TCh?": " <unknown>    - TCP/IP header pools\r\n",
  "Gdfm": " win32k!DoFontManagement              - GDITAG_HGLYPH_ARRAY\r\n",
  "Lrca": " <unknown>    -     Temporary storage used in name canonicalization\r\n",
  "PfOB": " nt!pf        - Pf Oplock buffers\r\n",
  "Lrcn": " <unknown>    -     Computer Name\r\n",
  "Lrcl": " <unknown>    -     ConnectListEntries\r\n",
  "DfC?": " dfsc.sys     - DFS Client allocations\r\n",
  "smFh": " nt!store     -         ReadyBoost cache file header\r\n",
  "PcPr": " <unknown>    - WDM audio stuff\r\n",
  "Usld": " win32k!GrowLogIfNecessary            - USERTAG_LOGDESKTOP\r\n",
  "PpEE": " nt!pnp       - PNP_DEVICE_EVENT_ENTRY_TAG\r\n",
  "TcEW": " tcpip.sys    - TCP Endpoint Work Queue Contexts\r\n",
  "Lrcx": " <unknown>    -     Context blocks of various types\r\n",
  "VSta": " storvsp.sys - Virtual Machine Storage VSP Driver (adapter)\r\n",
  "Trcd": " netiobvt.sys - NB Control Data\r\n",
  "Mem ": " nt!po        - NT Power manager, POP_MEM_TAG\r\n",
  "PsPb": " nt!ps        - Captured process parameter block (temporary allocation)\r\n",
  "Usla": " win32k!InitLockRecordLookaside       - USERTAG_LOOKASIDE\r\n",
  "thdd": " <unknown>    - DirectDraw/3D handle manager table\r\n",
  "FMnc": " fltmgr.sys   -       NAME_CACHE_CREATE_CTRL structure\r\n",
  "PcIc": " <unknown>    - WDM audio stuff\r\n",
  "PcIl": " <unknown>    - WDM audio stuff\r\n",
  "Gedd": " win32k.sys                           - GDITAG_ENUM_DISPLAY_DEVICES\r\n",
  "FIOc": " fileinfo.sys - FileInfo FS-filter Prefetch Open Context\r\n",
  "Gedg": " win32k!bFill                         - GDITAG_EDGE\r\n",
  "IoSi": " nt!io        - Io Symbolic Links\r\n",
  "IoSh": " nt!io        - Io shutdown packet\r\n",
  "KSpt": " <unknown>    -    pin type list (MSKSSRV)\r\n",
  "KSpp": " <unknown>    -    irp system buffer property/method/event parameter\r\n",
  "IoSn": " nt!io        - Io Session Notifications\r\n",
  "ClfS": " clfs.sys     - CLFS Log base file snapshot\r\n",
  "TMlt": " dxgkrnl!CTokenManager::EnsureLegacyTokenBuffer        - TOKENMANAGER_LEGACYTOKENBUFFER\r\n",
  "ClfP": " clfs.sys     - CLFS Log request state\r\n",
  "ClfO": " clfs.sys     - CLFS Log zero page\r\n",
  "ClfN": " clfs.sys     - CLFS Log base file lock\r\n",
  "ClfL": " clfs.sys     - CLFS Log base file image (obsolete)\r\n",
  "ClfK": " clfs.sys     - CLFS Log read completion element\r\n",
  "ClfJ": " clfs.sys     - CLFS Log MDL reference\r\n",
  "ClfI": " clfs.sys     - CLFS Log marshal buffer lookaside list\r\n",
  "ClfH": " clfs.sys     - CLFS Log I/O control block lookaside list\r\n",
  "ClfG": " clfs.sys     - CLFS Log I/O Request lookaside list\r\n",
  "ClfF": " clfs.sys     - CLFS Log flush element lookaside list\r\n",
  "ClfE": " clfs.sys     - CLFS Log CCB lookaside list\r\n",
  "ClfD": " clfs.sys     - CLFS Log virtual FCB lookaside list\r\n",
  "ClfC": " clfs.sys     - CLFS Log physical FCB lookaside list\r\n",
  "IoSt": " nt!io        - Io Stream Identifier Context\r\n",
  "ClfA": " clfs.sys     - CLFS Log container lookaside list\r\n",
  "MuPi": " mup.sys      - Provider info\r\n",
  "VadF": " nt!mm        - VADs created by a FreeVM splitting\r\n",
  "VsNb": " vmswitch.sys - Virtual Machine Network Switch Driver (NBL)\r\n",
  "PcPc": " <unknown>    - WDM audio stuff\r\n",
  "Clfs": " clfs.sys     - CLFS General buffer, or owner page lookaside list\r\n",
  "IoSD": " nt!io        - Io system device buffer\r\n",
  "VadS": " nt!mm        - Mm virtual address descriptors (short)\r\n",
  "LS??": " <unknown>    - LM server allocations\r\n",
  "DCem": " win32kbase!DirectComposition::CBaseExpressionMarshaler::SetBufferProperty                - DCOMPOSITIONTAG_EXPRESSIONTARGETMASK\r\n",
  "LBnn": " <unknown>    -     Name name\r\n",
  "COMX": " serial.sys   - serial driver allocations\r\n",
  "Vad ": " nt!mm        - Mm virtual address descriptors\r\n",
  "IIdt": " <unknown>    - Data\r\n",
  "RBSe": " <unknown>    - RedBook - Serialization tracking for checked builds\r\n",
  "SWki": " <unknown>    -         key information\r\n",
  "Ipcr": " tcpip.sys    - IP Cache-aware Reference Counters\r\n",
  "UsCd": " win32k!xxxUserChangeDisplaySettings  - USERTAG_CDS\r\n",
  "IPpa": " tcpip.sys    - IP Path information\r\n",
  "IPpo": " tcpip.sys    - IP Offload buffers\r\n",
  "TcLS": " tcpip.sys    - TCP Listener SockAddrs\r\n",
  "Pcmc": " pcmcia.sys   - Pcmcia bus enumerator, general structures\r\n",
  "DCyb": " win32kbase!DirectComposition::CSharedCompositionDistantLightMarshaler::_allocate         - DCOMPOSITIONTAG_SHAREDCOMPOSITIONDISTANTLIGHTMARSHALER\r\n",
  "NtFE": " ntfs.sys     -     Ea.c\r\n",
  "RRle": " <unknown>    - RTL_RANGE_LIST_ENTRY_TAG\r\n",
  "p2en": " perm2dll.dll - Permedia2 display driver - enable.c\r\n",
  "RaTQ": " storport.sys - RaUnitQueryDeviceTextIrp\r\n",
  "Cdun": " cdfs.sys     - CDFS Buffer for upcased name\r\n",
  "Fwpd": " fwpkclnt.sys - WFP delayed injection context\r\n",
  "KSbi": " <unknown>    -    event buffered item\r\n",
  "Wfp?": " netio.sys    - Windows Filtering Platform Tags\r\n",
  "TcST": " tcpip.sys    - TCP Syn TCBs\r\n",
  "RaTM": " storport.sys - RaInitializeTagList storport!_QUEUE_TAG_LIST.Buffer\r\n",
  "UcSc": " http.sys     - Common Server Information\r\n",
  "ATgb": " AppTag guid buffer\r\n",
  "TdxT": " tdx.sys      - TDX Transport Provider Contexts\r\n",
  "NMRg": " tcpip.sys    - Network Module Registrar Generic Buffers\r\n",
  "AuxL": " <unknown>    - EXIFS Auxlist\r\n",
  "NLcp": " tcpip.sys    - Network Layer Compartments\r\n",
  "DCba": " win32kbase!DirectComposition::CBatch::_allocate                                          - DCOMPOSITIONTAG_BATCH\r\n",
  "VbuW": " vmbus.sys    - Virtual Machine Bus Driver (WDF)\r\n",
  "DCbc": " win32kbase!DirectComposition::CChannel::_allocate                                        - DCOMPOSITIONTAG_CHANNEL\r\n",
  "RawE": " tcpip.sys    - Raw Socket Endpoints\r\n",
  "SeCL": " nt!se        - Security CONTEXT_TAG\r\n",
  "DCbf": " win32kbase!DirectComposition::Memory::Allocate                                           - DCOMPOSITIONTAG_BUFFER\r\n",
  "Ppio": " nt!pnp       - plug-and-play IO system APIs\r\n",
  "Ppin": " nt!pnp       - plug-and-play initialization\r\n",
  "SmKs": " mrxsmb10.sys    -      SMB1  Kerberos blob  (special build only)\r\n",
  "smMd": " rdyboost.sys -         ReadyBoost MDL allocation\r\n",
  "Dict": " storport.sys - StorCreateDictionary storport!_STOR_DICTIONARY.Entries\r\n",
  "smMb": " rdyboost.sys -         ReadyBoost MDL buffer\r\n",
  "IPmm": " <unknown>    - Message\r\n",
  "DCbs": " win32kbase!DirectComposition::CBatchSharedMemoryPool::_allocate                          - DCOMPOSITIONTAG_BATCH_SHARED_MEMORY_POOL\r\n",
  "DCbr": " win32kbase!DirectComposition::CBatch::CSystemResourceReference::_allocate                - DCOMPOSITIONTAG_BATCH_RESOURCEREF\r\n",
  "PmpR": " portmap.sys  - Portmap RPCB\r\n",
  "smMR": " rdyboost.sys -         ReadyBoot multi-read ranges\r\n",
  "DEtn": " devolume.sys - Drive extender range lock test node\r\n",
  "RawN": " tcpip.sys    - Raw Socket Nsi\r\n",
  "DEte": " devolume.sys - Drive extender data error message: DEVolume!DE_DATA_ERROR_MESSAGE\r\n",
  "FxL?": " wdfldr.sys   - KMDF Loader Pool allocation\r\n",
  "ReFd": " refs.sys     -     DirCtrl.c\r\n",
  "PmpA": " portmap.sys  - Portmap address list\r\n",
  "DEtx": " devolume.sys - Drive extender range lock test\r\n",
  "PmpC": " portmap.sys  - Portmap device context\r\n",
  "smMD": " nt!store or rdyboost.sys - ReadyBoost store stats MDL\r\n",
  "NDmo": " ndis.sys     - NDIS_TAG_M_OPEN_BLK\r\n",
  "DCye": " win32kbase!DirectComposition::CSharedReadCompositionLightMarshaler::_allocate            - DCOMPOSITIONTAG_SHAREDREADCOMPOSITIONLIGHTMARSHALER\r\n",
  "DEts": " devolume.sys - Drive extender splay tree test\r\n",
  "DEtr": " devolume.sys - Drive extender trace message\r\n",
  "PmpM": " portmap.sys  - Portmap mapping\r\n",
  "DEtw": " devolume.sys - Drive extender trim worker pauser: DEVolume!AutoPauseTrimWorker\r\n",
  "VmOb": " volmgrx.sys  - I/O objects\r\n",
  "Pwmi": " pacer.sys    - PACER WMI notifications\r\n",
  "FDev": " win32k.sys                           - GDITAG_UMFD_EVENT\r\n",
  "UlLS": " http.sys     - Ansi Log Data Buffer\r\n",
  "Txsp": " ntfs.sys     - TXF_SCB_PTR\r\n",
  "smCR": " nt!store or rdyboost.sys - ReadyBoost encryption allocation\r\n",
  "UlLT": " http.sys     - Binary Log Data Buffer\r\n",
  "EQQu": " tcpip.sys    - EQoS flow unit\r\n",
  "Hioc": " hcaport.sys - HCAPORT_TAG_IOC_SERVICE_TABLE\r\n",
  "Nhfs": " tcpip.sys    - NetIO Hash Function State Data\r\n",
  "Txsa": " ntfs.sys     - Txf sorted array item\r\n",
  "Txsc": " ntfs.sys     - TXF_SCB\r\n",
  "UlLG": " http.sys     - Log Generic\r\n",
  "UlLF": " http.sys     - Log File Entry\r\n",
  "CIcr": " ci.dll       - Code Integrity allocations for image integrity checking\r\n",
  "CM  ": " nt!cm        - Configuration Manager (registry)\r\n",
  "ScS2": " classpnp.sys - Sense interpretation data\r\n",
  "DCpv": " win32kbase!DirectComposition::CParticleEmitterVisualMarshaler::_allocate                 - DCOMPOSITIONTAG_PARTICLEEMITTERVISUALMARSHALER\r\n",
  "Uspi": " win32k!MapDesktop                    - USERTAG_PROCESSINFO\r\n",
  "DCjn": " win32kbase!DirectComposition::CNineGridBrushMarshaler::_allocate                         - DCOMPOSITIONTAG_NINEGRIDBRUSHMARSHALER\r\n",
  "DCpy": " win32kbase!DirectComposition::CPathGeometryMarshaler::_allocate                          - DCOMPOSITIONTAG_PATHGEOMETRYMARSHALER\r\n",
  "smCr": " nt!store     -         ReadyBoost store region bitmap\r\n",
  "IPba": " tcpip.sys    - IP Batching\r\n",
  "IIrf": " <unknown>    - Free memory\r\n",
  "wpvo": " wof.sys      - Wim volume overlay\r\n",
  "DCpb": " win32kbase!DirectComposition::CPropertySetMarshaler::_allocate                           - DCOMPOSITIONTAG_PROPERTYSETMARSHALER\r\n",
  "Uspk": " win32k!GetProductString              - USERTAG_PRODUCTSTRING\r\n",
  "DCpg": " win32kbase!DirectComposition::CPrimitiveGroupMarshaler::_allocate                        - DCOMPOSITIONTAG_PRIMITIVEGROUPMARSHALER\r\n",
  "FxLg": " wdf01000.sys - KMDF IFR log tag\r\n",
  "ATub": " AppTag user buffer\r\n",
  "DCpd": " win32kbase!DirectComposition::CProcessData::_allocate                                    - DCOMPOSITIONTAG_PROCESSDATA\r\n",
  "CBRe": " <unknown>    - CallbackRegistration\r\n",
  "Uspl": " win32k!xxxPollAndWaitForSingleObject - USERTAG_POLLEVENT\r\n",
  "IPbw": " tcpip.sys    - IP Path Bandwidth information\r\n",
  "DCpo": " win32kbase!DirectComposition::CCompositionPointLight::_allocate                          - DCOMPOSITIONTAG_POINTLIGHTMARSHALER\r\n",
  "Port": " <unknown>    - Port objects\r\n",
  "Uspm": " win32k!MNAllocPopup                  - USERTAG_POPUPMENU\r\n",
  "BCSP": " bthbcsp.sys  - Bluetooth BCSP minidriver\r\n",
  "ObNm": " nt!ob        - object names\r\n",
  "Uswr": " win32k!CoreWindowProp                - USERTAG_COREWINDOWPROP\r\n",
  "Uspn": " win32k!CreateProfileUserName         - USERTAG_PROFILEUSERNAME\r\n",
  "MNFr": " msnfsflt.sys - NFS FS Filter, registry access buffer\r\n",
  "NDrd": " ndis.sys     - NDIS_TAG_REG_READ_DATA_BUFFER\r\n",
  "NDre": " ndis.sys     - NDIS_TAG_OID_REQUEST\r\n",
  "NDrf": " ndis.sys     - NDIS_TAG_RECEIVE_FILTER\r\n",
  "TdxC": " tdx.sys      - TDX Connections\r\n",
  "Psap": " nt!ps        - Block used to hold a user mode APC while its queued to a thread\r\n",
  "Pcta": " pacer.sys    - PACER Timer Units\r\n",
  "NDrc": " ndis.sys     - NDIS_TAG_RWL_REFCOUNT\r\n",
  "Hist": " <unknown>    - histogram filter driver\r\n",
  "Nrsd": " netio.sys    - NRT security descriptor\r\n",
  "NDrx": " ndis.sys     - NDIS debugging refcount\r\n",
  "ReFW": " refs.sys     -     Write.c\r\n",
  "Uspa": " win32k!AllocPointerMsgParamsList     - USERTAG_POINTERMSGPARAMS\r\n",
  "NDrt": " ndis.sys     - NDIS_TAG_RST_NBL\r\n",
  "NDrw": " ndis.sys     - NDIS_TAG_RWLOCK\r\n",
  "NDrp": " ndis.sys     - NDIS_TAG_REGISTRY_PATH\r\n",
  "NDrq": " ndis.sys     - NDIS_TAG_Q_REQ\r\n",
  "NDrs": " ndis.sys     - NDIS_TAG_RSS\r\n",
  "PPT8": " <unknown>    - PPTP_SEND_CTRLDATA_TAG\r\n",
  "I6e": "  tcpip.sys    - IPv6 Echo data\r\n",
  "Usts": " win32k!_Win32CreateSection           - USERTAG_SECTION\r\n",
  "RpcL": " msrpc.sys    - debugging log data - present on checked builds only\r\n",
  "DClc": " win32kbase!DirectComposition::CVisualMarshaler::_allocate                                - DCOMPOSITIONTAG_LAYOUTCONSTRAINTINFO\r\n",
  "UlRD": " http.sys     - Registry Data\r\n",
  "HisC": " <unknown>    - histogram filter driver\r\n",
  "PPT0": " <unknown>    - PPTP_TDIADDR_TAG\r\n",
  "PPT1": " <unknown>    - PPTP_TDICONN_TAG\r\n",
  "PPT2": " <unknown>    - PPTP_CONNINFO_TAG\r\n",
  "PPT3": " <unknown>    - PPTP_ADDRINFO_TAG\r\n",
  "PPT4": " <unknown>    - PPTP_TIMEOUT_TAG\r\n",
  "PPT5": " <unknown>    - PPTP_TIMER_TAG\r\n",
  "PPT6": " <unknown>    - PPTP_TDICOTS_TAG\r\n",
  "PPT7": " <unknown>    - PPTP_WRKQUEUE_TAG\r\n",
  "p2??": " perm2dll.dll - Permedia2 display driver\r\n",
  "PSC2": " <unknown>    - WanLink\r\n",
  "DClt": " win32kbase!DirectComposition::CLinearObjectTableBase::_allocate                          - DCOMPOSITIONTAG_LINEAROBJECTTABLEDATA\r\n",
  "PcFM": " <unknown>    - WDM audio FM synthesizer\r\n",
  "PSC3": " <unknown>    - Miscellaneous allocations\r\n",
  "UdPM": " tcpip.sys    - UDP Partial Memory Descriptor Lists\r\n",
  "VubH": " vmusbbus.sys  - Virtual Machine USB Bus Driver\r\n",
  "Tdxt": " tdx.sys      - TDX Transport Layer Clients\r\n",
  "DEze": " devolume.sys - Drive extender cluster of zeros\r\n",
  "RaPC": " storport.sys - RaInitializeConfiguration storport!_PORT_CONFIGURATION_INFORMATION.AccessRanges\r\n",
  "NEIM": " newt_ndis6.sys - NEWT IM Object\r\n",
  "Cdee": " cdfs.sys     - CDFS Search expression for enumeration\r\n",
  "PPTP": " <unknown>    - PPTP_MEMORYPOOL_TAG\r\n",
  "IoSe": " nt!io        - Io security related\r\n",
  "ReFN": " refs.sys     -     NtfsData.c\r\n",
  "Ghab": " win32k!FHOBJ::bAddPFELink            - GDITAG_PFE_HASHBUCKET\r\n",
  "rbMd": " <unknown>    - RedBook - Mdl for read/stream\r\n",
  "SisC": " <unknown>    -         SIS common store file object\r\n",
  "VfAT": " nt!Vf        - Verifier AVL trees\r\n",
  "Tdxp": " tdx.sys      - TDX Reserved Page Tables Entries\r\n",
  "PRF?": " nt!wdi       - Performance Allocations\r\n",
  "ISLe": " tcpip.sys    - IPsec SA list entry\r\n",
  "WSCD": " WFPSamplerCalloutDriver.sys - WFPSampler Callout Driver\r\n",
  "FDrq": " win32k.sys                           - GDITAG_UMFD_REQUEST\r\n",
  "Gtxt": " win32k.sys                           - GDITAG_TEXT\r\n",
  "BTPT": " <unknown>    - Bluetooth transport protocol library\r\n",
  "VmWi": " volmgrx.sys  - Work items\r\n",
  "FMrl": " fltmgr.sys   -       FLT_OBJECT rundown logs\r\n",
  "ReFD": " refs.sys     -     DevioSup.c\r\n",
  "PPTh": " <unknown>    - PPTP_ENGINE_TAG\r\n",
  "PPTi": " <unknown>    - PPTP_RECVDATA_TAG\r\n",
  "MSls": " refs.sys     - Minstore logged stack\r\n",
  "MmFr": " nt!mm        - ASLR fixup records\r\n",
  "UspQ": " win32k!AllocPointerQFrameList        - USERTAG_POINTERQFRAME\r\n",
  "FMrp": " fltmgr.sys   -       Reparse point data buffer\r\n",
  "FMrs": " fltmgr.sys   -       Registry string\r\n",
  "FMrr": " fltmgr.sys   -       Per-processor Cache-aware rundown ref structure\r\n",
  "PPTd": " <unknown>    - PPTP_RECV_CTRLDATA_TAG\r\n",
  "PPTe": " <unknown>    - PPTP_RECV_DGRAMDESC_TAG\r\n",
  "FMrw": " fltmgr.sys   -       FLT_REGISTRY_WATCH_CONTEXT structure\r\n",
  "KSpc": " <unknown>    -    port driver instance FsContext\r\n",
  "NDnd": " ndis.sys     - NDIS_TAG_POOL_NDIS\r\n",
  "TcDM": " tcpip.sys    - TCP Delayed Delivery Memory Descriptor Lists\r\n",
  "p2tx": " perm2dll.dll - Permedia2 display driver - textout.c\r\n",
  "TcDD": " tcpip.sys    - TCP Debug Delivery Buffers\r\n",
  "Wmiz": " <unknown>    - Wmi MCA Insertions debug code\r\n",
  "DCrt": " win32kbase!DirectComposition::CResourceTable::_allocate                                  - DCOMPOSITIONTAG_RESOURCETABLE\r\n",
  "Vi12": " dxgmms2.sys  - Video memory manager process heap alloc\r\n",
  "Nba9": " netbt.sys    - NetBT IP request buffer\r\n",
  "MSvc": " refs.sys     - Minstore volume context\r\n",
  "Gcwc": " win32k!ConvertToAndFromWideChar      - GDITAG_CHAR_TO_WIDE_CHAR\r\n",
  "Ithp": " tcpip.sys    - IPsec throttle parameter\r\n",
  "TcDR": " tcpip.sys    - TCP Disconnect Requests\r\n",
  "TcDQ": " tcpip.sys    - TCP Delay Queues\r\n",
  "Itht": " tcpip.sys    - IPsec hashtable\r\n",
  "PfVH": " nt!pf        - Pf Prefetch volume handles\r\n",
  "RfWR": " rfcomm.sys   -   RFCOMM worker\r\n",
  "MuPe": " mup.sys      - Known prefix entry\r\n",
  "RWan": " rawwan.sys   - Raw WAN driver\r\n",
  "PsSd": " nt!ps        - Augmented thread security descriptor (temporary allocation)\r\n",
  "ClfB": " clfs.sys     - CLFS Log base file lookaside list\r\n",
  "NCSt": " <unknown>    - EXIFS NC\r\n",
  "RSQI": " <unknown>    -      Queue info\r\n",
  "Gogl": " win32k!iOpenGLExtEscape              - GDITAG_OPENGL\r\n",
  "SisS": " <unknown>    -         SIS SCB\r\n",
  "G???": " <unknown>    - Gdi Objects\r\n",
  "UlPB": " http.sys     - APool Proc Binding\r\n",
  "ObNM": " nt!ob        - name buffer per processor lookaside pointers\r\n",
  "AzMu": " HDAudio.sys  - HD Audio Class Driver (MuxedCapture)\r\n",
  "Gppo": " win32k!XCLIPOBJ::ppoGetPath          - GDITAG_CLIP_PATHOBJ\r\n",
  "IrD?": " <unknown>    - IrDA TDI and RAS drivers\r\n",
  "NtAR": " ntfs.sys     -     Ntfs Async Cached Read allocation\r\n",
  "AzMx": " HDAudio.sys  - HD Audio Class Driver (AzMixerport)\r\n",
  "LS04": " srvnet.sys   -     SRVNET LookasideList level 4 allocation 4K Bytes\r\n",
  "AzMa": " HDAudio.sys  - HD Audio Class Driver (Main)\r\n",
  "Tdxn": " tdx.sys      - TDX Net Addresses\r\n",
  "AzMi": " HDAudio.sys  - HD Audio Class Driver (micin, MixedCapture)\r\n",
  "Tdxo": " tdx.sys      - TDX Device Objects\r\n",
  "DWMt": " win32k.sys                           - GDITAG_DWM_SENDTOUCHCONTACTS\r\n",
  "DWMv": " win32k.sys                           - GDITAG_DWM_VALIDATION\r\n",
  "Ustz": " win32k!AllocTouchInputInfo           - USERTAG_TOUCHINPUTINFO\r\n",
  "CdA ": " <unknown>    - CdAudio filter driver\r\n",
  "NeWQ": " tcpip.sys    - NetIO WorkQueue Data\r\n",
  "VHps": " vmusbhub.sys - Virtual Machine USB Hub Driver (Pnp string)\r\n",
  "Gmul": " win32k!MULTIFONT::MULTIFONT          - GDITAG_MULTIFONT\r\n",
  "IPss": " tcpip.sys    - IP Session State\r\n",
  "NDDl": " ndis.sys     - NDIS_TAG_DBG_LOG\r\n",
  "VmCo": " volmgrx.sys  - Configurations\r\n",
  "Wrps": " <unknown>    - WAN_STRING_TAG\r\n",
  "EQCc": " tcpip.sys    - EQoS counters\r\n",
  "Wrpw": " <unknown>    - WAN_PACKET_TAG\r\n",
  "SPX ": " <unknown>    - Nwlnkspx transport\r\n",
  "Pclt": " pacer.sys    - PACER Line Tables\r\n",
  "Wrpi": " <unknown>    - WAN_INTERFACE_TAG\r\n",
  "NpEv": " npfs.sys     - Npfs events\r\n",
  "Wrpn": " <unknown>    - WAN_NOTIFICATION_TAG\r\n",
  "NpFW": " npfs.sys     - Write block\r\n",
  "V2lg": " vhdmp.sys    - VHD2 core large allocation\r\n",
  "Wrpc": " <unknown>    - WAN_CONN_TAG\r\n",
  "Wrpa": " <unknown>    - WAN_ADAPTER_TAG\r\n",
  "IPsi": " tcpip.sys    - IP SubInterfaces\r\n",
  "TmNo": " nt!tm        - Tm Notification\r\n",
  "CcDw": " nt!cc        - Cache Manager Deferred Write\r\n",
  "Pcle": " pacer.sys    - PACER Lines\r\n",
  "Wrpd": " <unknown>    - WAN_DATA_TAG\r\n",
  "usmd": " win32k!xxxSetModernAppWindow         - USERTAG_MODERNDESKTOPAPP\r\n",
  "svx?": " svhdxflt.sys - VHDX sharing among multiple Hyper-V guests\r\n",
  "VmCh": " ChimneyLib.lib  - Virtual Machine Network Chimney Library\r\n",
  "KScp": " <unknown>    -    object creation parameters auxiliary copy\r\n",
  "Uswl": " win32k!BuildHwndList                 - USERTAG_WINDOWLIST\r\n",
  "IoBo": " nt!io        - Io boot disk information\r\n",
  "KSci": " <unknown>    -    default clock instance header\r\n",
  "KSch": " <unknown>    -    create handler entry\r\n",
  "PepT": " nt!PopPep    - Default Power Engine Plugin\r\n",
  "KSce": " <unknown>    -    create item entry\r\n",
  "RaWM": " storport.sys - RaidAdapterWmiDeferredRoutine\r\n",
  "FS??": " nt!fsrtl     - Unrecoginzed File System Run Time allocations (update pooltag.w)\r\n",
  "TSic": " termdd.sys   - Terminal Services - ICA_POOL_TAG\r\n",
  "Wrp?": " <unknown>    - WanArp Tags (ARP module for Remote Access)\r\n",
  "NDpb": " ndis.sys     -     protocol block\r\n",
  "svxS": " svhdxflt.sys -         Stream handle context\r\n",
  "VoSt": " volsnap.sys  -      Temp table allocations\r\n",
  "svxQ": " svhdxflt.sys -         Persistent Reservation - Device context\r\n",
  "svxP": " svhdxflt.sys -         Persistent Reservation - Registrations\r\n",
  "_ATI": " <unknown>    - ATI video driver\r\n",
  "Cngb": " ksecdd.sys   - CNG kmode crypto pool tag\r\n",
  "NLNa": " tcpip.sys    - Network Layer Network Address Lists\r\n",
  "svxI": " svhdxflt.sys -         Initiator lists\r\n",
  "PsEx": " nt!ps        - Process exit APC\r\n",
  "VoSw": " volsnap.sys  -      Work queue allocations\r\n",
  "Ippp": " tcpip.sys    - IP Prefix Policy information\r\n",
  "svxs": " svhdxflt.sys -         Stream context\r\n",
  "FSmg": " nt!fsrtl     - File System Run Time\r\n",
  "svxq": " svhdxflt.sys -         Persistent Reservation - Reservation Info\r\n",
  "svxp": " svhdxflt.sys -         Persistent Reservation support for shared VHDX files\r\n",
  "svxw": " svhdxflt.sys -         File write operations\r\n",
  "IPfp": " tcpip.sys    - IP PreValidated Receives\r\n",
  "svxt": " svhdxflt.sys -         Test Filter\r\n",
  "LScd": " srv.sys      -     SMB1 comm device\r\n",
  "UlFC": " http.sys     - File Cache Entry\r\n",
  "svxl": " svhdxflt.sys -         Shared VHDX RTL\r\n",
  "LScn": " srv.sys      -     SMB1 connection\r\n",
  "VcSn": " rdpdr.sys - Dynamic Virtual session object\r\n",
  "MmHt": " nt!mm        - session space PTE data\r\n",
  "ObTR": " nt!ob        - object table ERESOURCEs\r\n",
  "svxe": " svhdxflt.sys -         Stored sense data errors\r\n",
  "svxd": " svhdxflt.sys -         SVHDX communications port\r\n",
  "DcbI": " msdcb.sys    - DCB interface context\r\n",
  "AlLl": " tcpip.sys    -     ALE remote endpoint LRU\r\n",
  "PSC?": " <unknown>    - Packet Scheduler (PSCHED) Tags\r\n",
  "DcbL": " msdcb.sys    - DCB LLDP buffer\r\n",
  "DcbA": " msdcb.sys    - DCB application priority\r\n",
  "FMct": " fltmgr.sys   -       TRACK_COMPLETION_NODES structure\r\n",
  "Rnm ": " rndismp.sys  - RNDIS MP driver generic alloc\r\n",
  "FMcr": " fltmgr.sys   -       Context registration structures\r\n",
  "DcbD": " msdcb.sys    - DCB NDIS_QOS_CONFIGURATION\r\n",
  "FMcp": " fltmgr.sys   -       Client port wrapper structure\r\n",
  "DCls": " win32kbase!DirectComposition::CVisualSurfaceMarshaler::_allocate                         - DCOMPOSITIONTAG_VISUALSURFACEMARSHALER\r\n",
  "FMcn": " fltmgr.sys   -       Non paged context extension structures\r\n",
  "DcbX": " msdcb.sys    - DCB general\r\n",
  "PXi": " ndproxy.sys - PX_VC_TAG\r\n",
  "PXh": " ndproxy.sys - PX_CLAF_TAG\r\n",
  "VdDr": " Vid.sys - Virtual Machine Virtualization Infrastructure Driver\r\n",
  "NDd ": " ndis.sys     - NDIS_TAG_DBG\r\n",
  "Uspd": " win32k!PointerList::AddMsgData       - USERTAG_POINTERINPUTMSGDATA\r\n",
  "PXl": " ndproxy.sys - PX_LINETABLE_TAG\r\n",
  "PXc": " ndproxy.sys - PX_ENUMADDR_TAG\r\n",
  "DcbP": " msdcb.sys    - DCB NDIS port information\r\n",
  "DcbS": " msdcb.sys    - DCB security object\r\n",
  "DcbR": " msdcb.sys    - DCB store change record\r\n",
  "FMcb": " fltmgr.sys   -       FLT_CCB structure\r\n",
  "DVEx": " <unknown>    - Exchange, DAV MiniRedir\r\n",
  "PXe": " ndproxy.sys - PX_TAPICALL_TAG\r\n",
  "PXd": " ndproxy.sys - PX_TAPIADDR_TAG\r\n",
  "UlOE": " http.sys     - Endpoint OwnerRefTraceLog PoolTag\r\n",
  "VfPT": " nt!Vf        - Verifier Allocate/Free Pool stack traces\r\n",
  "IIsc": " <unknown>    - Send Context\r\n",
  "Symb": " <unknown>    - Symbolic link objects\r\n",
  "DCst": " win32kbase!DirectComposition::CScaleTransformMarshaler::_allocate                        - DCOMPOSITIONTAG_SCALETRANSFORMMARSHALER\r\n",
  "DCss": " win32kbase!DirectComposition::CSharedSectionMarshaler                                    - DCOMPOSITIONTAG_SHAREDSECTIONMARSHALER\r\n",
  "DCsp": " win32kbase!DirectComposition::CCompositionSpotLight::_allocate                           - DCOMPOSITIONTAG_SPOTLIGHTMARSHALER\r\n",
  "DCsn": " win32kbase!DirectComposition::CSharedWriteScalarMarshaler::_allocate                     - DCOMPOSITIONTAG_SHAREDWRITESCALARMARSHALER\r\n",
  "DCso": " win32kbase!DirectComposition::CSemaphore::_allocate                                      - DCOMPOSITIONTAG_SEMAPHORE\r\n",
  "UlOT": " http.sys     - Opaque ID Table\r\n",
  "DCsm": " win32kbase!DirectComposition::CSharedReadScalarMarshaler::_allocate                      - DCOMPOSITIONTAG_SHAREDREADSCALARMARSHALER\r\n",
  "TcWQ": " tcpip.sys    - TCP TCB Work Queue Contexts\r\n",
  "VoSf": " volsnap.sys  -      Diff area file allocations\r\n",
  "DCsh": " win32kbase!DirectComposition::CShapeVisualMarshaler::_allocate                           - DCOMPOSITIONTAG_SHAPEVISUALMARSHALER\r\n",
  "MSde": " refs.sys     - Minstore dirty table tracking\r\n",
  "DCsd": " win32kbase!DirectComposition::CSpriteShapeMarshaler::SetBufferProperty                   - DCOMPOSITIONTAG_STROKEDASHARRAY\r\n",
  "DCse": " win32kbase!DirectComposition::CSynchronizationManager::_allocate                         - DCOMPOSITIONTAG_SYNCHRONIZATIONENTRY\r\n",
  "DCsb": " win32kbase!DirectComposition::CCompositionSkyBoxBrushMarshaler::_allocate                - DCOMPOSITIONTAG_SKYBOXBRUSHMARSHALER\r\n",
  "Toke": " nt!se        - Token objects\r\n",
  "CMTr": " nt!cm        - Configuration Manager Transaction Tag\r\n",
  "DCsa": " win32kbase!DirectComposition::CSnapshotMarshaler::_allocate                              - DCOMPOSITIONTAG_SNAPSHOTMARSHALER\r\n",
  "PX9": " ndproxy.sys - PX_PROVIDER_TAG\r\n",
  "KSqr": " <unknown>    -    QM quality report\r\n",
  "ReFV": " refs.sys     -     VerfySup.c\r\n",
  "Usta": " win32k!AssociateShellFrameAppThreads - USERTAG_THREADASSOCIATION\r\n",
  "DCnl": " win32kbase!DirectComposition::CDeletedNotificationList::_allocate                        - DCOMPOSITIONTAG_DELETEDNOTIFICATIONLIST\r\n",
  "PX3": " ndproxy.sys - PX_ADAPTER_TAG\r\n",
  "PX2": " ndproxy.sys - PX_VCTABLE_TAG\r\n",
  "PX1": " ndproxy.sys - PX_EVENT_TAG\r\n",
  "Qnam": " <unknown>    - EXIFS Query Name\r\n",
  "Alep": " tcpip.sys    -     ALE process info\r\n",
  "PX6": " ndproxy.sys - PX_PARTY_TAG\r\n",
  "PX5": " ndproxy.sys - PX_CMSAP_TAG\r\n",
  "PX4": " ndproxy.sys - PX_CLSAP_TAG\r\n",
  "MuQc": " mup.sys      - Query context\r\n",
  "TmDn": " nt!tm        - Tm Dynamic Name\r\n",
  "Alei": " tcpip.sys    -     ALE arrival/nexthop interface cache\r\n",
  "KSqf": " <unknown>    -    query information file buffer\r\n",
  "Rnms": " rndismp.sys  - RNDIS MP driver send frame\r\n",
  "FtM ": " <unknown>    - Fault tolerance driver\r\n",
  "DEec": " devolume.sys - Drive extender ECC Page: DEVolume!DeEccPage\r\n",
  "DrIC": " rdpdr.sys    - I/O context object\r\n",
  "DEea": " devolume.sys - Drive extender expanding array: DEVolume!ExpandingAutoPointerArray<T>\r\n",
  "wpgn": " wof.sys      - Wim general\r\n",
  "Uiso": " win32k!TypeIsolation::Create         - USERTAG_ISOHEAP\r\n",
  "AleU": " tcpip.sys    -     ALE pend context\r\n",
  "AleW": " tcpip.sys    -     ALE enum filter array\r\n",
  "AleP": " tcpip.sys    -     ALE process image path\r\n",
  "VmP3": " volmgrx.sys  - Huge packets\r\n",
  "AleS": " tcpip.sys    -     ALE token info\r\n",
  "AleL": " tcpip.sys    -     ALE LRU\r\n",
  "IpTI": " ipsec.sys    -  timers\r\n",
  "Wmin": " <unknown>    - Wmi Notification Slot Chunks\r\n",
  "AleI": " tcpip.sys    -     ALE token ID\r\n",
  "AleK": " tcpip.sys    -     ALE audit\r\n",
  "AleD": " tcpip.sys    -     ALE remote endpoint\r\n",
  "AleE": " tcpip.sys    -     ALE endpoint context\r\n",
  "AleA": " tcpip.sys    -     ALE connection abort context\r\n",
  "Cddn": " cdfs.sys     - CDFS CdName in dirent\r\n",
  "Dcl ": " <unknown>    - cirrus video driver\r\n",
  "NDAg": " ndis.sys     - NDIS_PD_GLOBAL\r\n",
  "VmNe": " volmgrx.sys  - Notification entries\r\n",
  "SisL": " <unknown>    -         SIS per link object\r\n",
  "TSmc": " <unknown>    - PDMCS - Hydra MCS Protocol Driver\r\n",
  "SmVc": " mrxsmb.sys    - SMB VC endpoint\r\n",
  "Ipft": " tcpip.sys    - IPsec filter\r\n",
  "ScP?": " <unknown>    -   Scsiport\r\n",
  "LBse": " <unknown>    -     Browser security\r\n",
  "RhHi": " tcpip.sys    - Reference History Pool\r\n",
  "Afdc": " afd.sys      -     Afd connect data buffer\r\n",
  "Evid": " <unknown>    - Rtl Event ID's\r\n",
  "LBsl": " <unknown>    -     Browser server list\r\n",
  "DCau": " win32kbase!DirectComposition::CSharedReadAnimationTriggerMarshaler::_allocate            - DCOMPOSITIONTAG_SHAREDREADANIMATIONTRIGGERMARSHALER\r\n",
  "VmVd": " volmgrx.sys  - Volume devices\r\n",
  "ScV?": " <unknown>    -  Dvd functionality in cdrom.sys\r\n",
  "Symt": " <unknown>    - Symbolic link target strings\r\n",
  "PSCe": " <unknown>    - ClassMapContext\r\n",
  "Umam": " win32k!UpdateDesktopThresholds       - USERTAG_MONITOR_MARGIN\r\n",
  "GVsf": " win32k!MulCreateDeviceBitmap         - GDITAG_MDSURF\r\n",
  "KbdC": " kbdclass.sys - Keyboard Class Driver\r\n",
  "Usha": " win32k!AllocateHidData               - USERTAG_HIDDATA\r\n",
  "smNp": " nt!store or rdyboost.sys - ReadyBoost store node pool allocations\r\n",
  "Getc": " win32k!GdiHandleEntryTable::_Create  - GDITAG_HANDLE_ENTRY_TABLE\r\n",
  "ScPZ": " <unknown>    -      Device name buffer\r\n",
  "Ushf": " win32k!AllocateHidConfigDesc         - USERTAG_HIDFEATURE\r\n",
  "ScPY": " <unknown>    -      Report Targets\r\n",
  "ScPV": " <unknown>    -      Device map allocations\r\n",
  "ScPW": " <unknown>    -      Wmi Requests\r\n",
  "ScPT": " <unknown>    -      interface mapping\r\n",
  "KbdH": " kbdhid.sys   - Keyboard HID mapper Driver\r\n",
  "Ushl": " win32k!INLPHLPSTRUCT                 - USERTAG_HELP\r\n",
  "ScPS": " <unknown>    -      registry allocations\r\n",
  "TmRi": " nt!tm        - Tm Recovery Information\r\n",
  "ScPQ": " <unknown>    -      request sense\r\n",
  "Ushp": " win32k!GetDeviceParent               - USERTAG_HIDPARENT\r\n",
  "ScDb": " classpnp.sys -      ClassPnP debug globals buffer\r\n",
  "ScPL": " <unknown>    -      scatter gather lists\r\n",
  "fpcx": " wof.sys      - Compressed file IO context\r\n",
  "Usht": " win32k!AllocateProcessHidTable       - USERTAG_HIDTABLE\r\n",
  "TmRr": " nt!tm        - Tm KTM_RESTART_RECORD\r\n",
  "Feiv": " netio.sys    - WFP filter engine incoming values\r\n",
  "ScPI": " <unknown>    -      Init data chain\r\n",
  "IpFI": " ipsec.sys    -  filter blocks\r\n",
  "ScPG": " <unknown>    -      Global memory\r\n",
  "ScPD": " <unknown>    -      SRB_DATA allocations\r\n",
  "ScPE": " <unknown>    -      Scatter gather lists\r\n",
  "ScPB": " <unknown>    -      Queuetag BitMap\r\n",
  "ScPC": " <unknown>    -      reset bus code\r\n",
  "fpct": " wof.sys      - Compressed file chunk table\r\n",
  "SmDO": " mrxsmb10.sys    -      SMB1   deferred open context  (special build only)\r\n",
  "UshD": " Win32k!AllocateHidDesc               - USERTAG_HIDDESC\r\n",
  "DCzs": " win32kbase!DirectComposition::CProjectedShadowSceneMarshaler::_allocate                  - DCOMPOSITIONTAG_PROJECTEDSHADOWSCENEMARSHALER\r\n",
  "ScPx": " <unknown>    -      Report Luns\r\n",
  "Cdvp": " cdfs.sys     - CDFS Vpb allocated in filesystem\r\n",
  "ScPv": " <unknown>    -      KEVENT\r\n",
  "ScPw": " <unknown>    -      Wmi Events\r\n",
  "ScPt": " <unknown>    -      legacy request rerouting\r\n",
  "ScPu": " <unknown>    -      device relation structs\r\n",
  "PfNL": " nt!pf        - Pf Name logging buffers\r\n",
  "SeLa": " nt!se        - Security Learning Mode ACLs\r\n",
  "ScPp": " <unknown>    -      device & adapter enable\r\n",
  "ScPq": " <unknown>    -      inquiry data\r\n",
  "UlQL": " http.sys     - TCI Flow\r\n",
  "TMac": " dxgkrnl!CAdapter::Create                              - TOKENMANAGER_ADAPTER\r\n",
  "ScPl": " <unknown>    -      remove lock tracking\r\n",
  "Cdvd": " cdfs.sys     - CDFS Buffer for volume descriptor\r\n",
  "UshT": " win32k!AllocateAndLinkHidTLCInfo     - USERTAG_HIDTLC\r\n",
  "UlQI": " http.sys     - TCI Interface\r\n",
  "ScPh": " <unknown>    -      HwDevice Ext\r\n",
  "FtC ": " <unknown>    - Fault tolerance driver\r\n",
  "Rind": " tcpip.sys    - Raw Socket Receive Indications\r\n",
  "ScPd": " <unknown>    -      Pnp id strings\r\n",
  "SeLw": " nt!se        - Security LSA Work Item\r\n",
  "ScPb": " <unknown>    -      Get Bus Dat Holder\r\n",
  "IpFl": " mpsdrv.sys   - MPSDRV IP Flow\r\n",
  "ScPa": " <unknown>    -      Hold registry data\r\n",
  "Ubwd": " win32kbase!NtMITMinuserWindowCreated - USERTAG_BASE_WINDOW\r\n",
  "NtFQ": " ntfs.sys     -     QuotaSup.c\r\n",
  "AzLs": " HDAudio.sys  - HD Audio Class Driver (DLTest)\r\n",
  "NtFS": " ntfs.sys     -     SecurSup.c\r\n",
  "ScLF": " classpnp.sys -      File Object Extension\r\n",
  "NtFU": " ntfs.sys     -     usnsup.c\r\n",
  "NtFV": " ntfs.sys     -     VerfySup.c\r\n",
  "NtFW": " ntfs.sys     -     Write.c\r\n",
  "LSpr": " srv.sys      -     SMB1 paged RFCB\r\n",
  "WlCb": " writelog.sys - Writelog checkpoint buffer\r\n",
  "ScLM": " classpnp.sys -      Media Change Detection\r\n",
  "NtFA": " ntfs.sys     -     AttrSup.c\r\n",
  "NtFB": " ntfs.sys     -     BitmpSup.c\r\n",
  "NtFC": " ntfs.sys     -     Create.c\r\n",
  "NtFD": " ntfs.sys     -     DevioSup.c\r\n",
  "AzLd": " HDAudio.sys  - HD Audio Class Driver (Datastore: logical device)\r\n",
  "AzLg": " HDAudio.sys  - HD Audio Class Driver (debug)\r\n",
  "Uman": " win32k!NtUserSetManipulationInputTarget - USERTAG_DWM_MANIPULATION\r\n",
  "AzLi": " HDAudio.sys  - HD Audio Class Driver (CDIn,AUXIn, linein)\r\n",
  "NtFI": " ntfs.sys     -     IndexSup.c\r\n",
  "DCsj": " win32kbase!DirectComposition::CSharedReadInteractionMarshaler::_allocate                 - DCOMPOSITIONTAG_SHAREDREADINTERACTIONMARSHALER\r\n",
  "NtFL": " ntfs.sys     -     LogSup.c\r\n",
  "NtFM": " ntfs.sys     -     McbSup.c\r\n",
  "NtFN": " ntfs.sys     -     NtfsData.c\r\n",
  "NtFO": " ntfs.sys     -     ObjIdSup.c\r\n",
  "ScLc": " classpnp.sys -      Cache filters\r\n",
  "MST?": " <unknown>    - MSTEE (mstee.sys)\r\n",
  "ScLf": " classpnp.sys -      Fault prediction\r\n",
  "NtFv": " ntfs.sys     -     ViewSup.c\r\n",
  "ScVK": " <unknown>    -      write buffer for DVD keys\r\n",
  "Lrsx": " <unknown>    -     Send contexts\r\n",
  "NtFa": " ntfs.sys     -     AllocSup.c\r\n",
  "Lrse": " <unknown>    -     Security entry\r\n",
  "ScLq": " classpnp.sys -      Release queue\r\n",
  "Lrsc": " <unknown>    -     Search Control Blocks\r\n",
  "ScLw": " classpnp.sys -      WMI\r\n",
  "NtFf": " ntfs.sys     -     FsCtrl.c\r\n",
  "Lrso": " <unknown>    -     Operating system name\r\n",
  "Lrsm": " <unknown>    -     SMB buffer\r\n",
  "Lrsl": " <unknown>    -     ServerListEntries\r\n",
  "NtFm": " ntfs.sys     -     Ntfs MFT View Ref Counter Arrays\r\n",
  "PsHl": " nt!ps        - Captured list of handles to inherit in child process (temporary allocation)\r\n",
  "NDsm": " ndis.sys     - Cached shared memory descriptor\r\n",
  "NDsk": " ndis.sys     - NDIS debugging stacktrace\r\n",
  "UlHc": " http.sys     - Http Connection RefTraceLog\r\n",
  "NDsi": " ndis.sys     - EISA slot information\r\n",
  "NDsh": " ndis.sys     - NDIS_TAG_SHARED_MEMORY\r\n",
  "NDsg": " ndis.sys     - NDIS_TAG_DOUBLE_BUFFER_PKT\r\n",
  "smPl": " rdyboost.sys -         ReadyBoot pended IRP lists\r\n",
  "NDse": " ndis.sys     - NDIS_TAG_SECURITY\r\n",
  "NDsd": " ndis.sys     - NDIS_TAG_NET_CFG_SEC_DESC\r\n",
  "smRg": " nt!store or rdyboost.sys - ReadyBoost in-memory store region array\r\n",
  "PmME": " partmgr.sys  - Partition Manager migration entry\r\n",
  "_LCD": " monitor.sys  - Monitor PDO name buffer\r\n",
  "Npf*": " npfs.sys     - Npfs Allocations\r\n",
  "Vi5a": " dxgmms2.sys  - Video memory manager PTE owner data\r\n",
  "Gtmw": " win32k!vIFIMetricsToTextMetricW      - GDITAG_TEXTMETRICS\r\n",
  "Nbb0": " netbt.sys    - NetBT IP request buffer\r\n",
  "NDst": " ndis.sys     - NDIS_TAG_STRING\r\n",
  "NDss": " ndis.sys     - NDIS_TAG_SS - Selective Suspend\r\n",
  "Gtmp": " win32k.sys                           - GDITAG_TEMP\r\n",
  "VoSp": " volsnap.sys  -      Pnp id allocations\r\n",
  "Glnk": " win32k!FHOBJ::bAddPFELink            - GDITAG_PFE_LINK\r\n",
  "Gdxd": " <unknown>    -     Gdi ddraw VPE directdraw object\r\n",
  "BDD ": " BasicDisplay.sys - Microsoft Basic Display Driver\r\n",
  "Cont": " <unknown>    - Contiguous physical memory allocations for device drivers\r\n",
  "MSTp": " <unknown>    -    pin instance\r\n",
  "MSTs": " <unknown>    -    stream header\r\n",
  "DCos": " win32kbase!DirectComposition::CSpriteShapeMarshaler::_allocate                           - DCOMPOSITIONTAG_SPRITESHAPEMARSHALER\r\n",
  "Uswi": " win32k!RemoteShadowStart             - USERTAG_WIREDATA\r\n",
  "DCsi": " win32kbase!DirectComposition::CSharedInteractionMarshaler::_allocate                     - DCOMPOSITIONTAG_SHAREDINTERACTIONMARSHALER\r\n",
  "Gdxs": " <unknown>    -     Gdi ddraw VPE surface, videoport, capture object\r\n",
  "MSTd": " <unknown>    -    data format\r\n",
  "MSTf": " <unknown>    -    filter instance\r\n",
  "Drsd": " <unknown>    - Rasdd Printer Driver Pool Tag.\r\n",
  "smXt": " nt!store or rdyboost.sys - ReadyBoost store extents array\r\n",
  "Gdxx": " <unknown>    -     Gdi ddraw VPE DXAPI object\r\n",
  "MSTc": " <unknown>    -    filer connection\r\n",
  "NbtA": " netbt.sys    - NetBT datagram\r\n",
  "NbtC": " netbt.sys    - NetBT address element\r\n",
  "NbtD": " netbt.sys    - NetBT connection\r\n",
  "NbtF": " netbt.sys    - NetBT remote name\r\n",
  "NbtG": " netbt.sys    - NetBT datagram\r\n",
  "NbtH": " netbt.sys    - NetBT work item context\r\n",
  "Gsem": " win32k.sys                           - GDITAG_SEMAPHORE\r\n",
  "NbtJ": " netbt.sys    - NetBT receive element\r\n",
  "NbtK": " netbt.sys    - NetBT name address\r\n",
  "IITn": " <unknown>    - Tunnel\r\n",
  "NbtM": " netbt.sys    - NetBT address list\r\n",
  "NbtN": " netbt.sys    - NetBT address list\r\n",
  "NbtO": " netbt.sys    - NetBT adapter status\r\n",
  "NbtP": " netbt.sys    - NetBT connection list\r\n",
  "NbtQ": " netbt.sys    - NetBT name stats\r\n",
  "NbtR": " netbt.sys    - NetBT name address\r\n",
  "NbtS": " netbt.sys    - NetBT datagram\r\n",
  "ScpP": " <unknown>    -      scsi PortConfig copies\r\n",
  "NbtV": " netbt.sys    - NetBT work item context\r\n",
  "NbtX": " netbt.sys    - NetBT datagram\r\n",
  "NbtY": " netbt.sys    - NetBT datagram\r\n",
  "NbtZ": " netbt.sys    - NetBT datagram\r\n",
  "MuFc": " mup.sys      - File Context\r\n",
  "DCbl": " win32kbase!DirectComposition::CBackChannelMarshaler::_allocate                           - DCOMPOSITIONTAG_BACKCHANNELMARSHALER\r\n",
  "Nbta": " netbt.sys    - NetBT DPC\r\n",
  "Nbtb": " netbt.sys    - NetBT NetBIOS address\r\n",
  "Nbtc": " netbt.sys    - NetBT address info\r\n",
  "Nbte": " netbt.sys    - NetBT delayed connect\r\n",
  "Nbtf": " netbt.sys    - NetBT DPC\r\n",
  "Nbtg": " netbt.sys    - NetBT MDL buffer\r\n",
  "Nbti": " netbt.sys    - NetBT device list\r\n",
  "Nbtj": " netbt.sys    - NetBT EA buffer\r\n",
  "Nbtk": " netbt.sys    - NetBT transport address\r\n",
  "Nbtm": " netbt.sys    - NetBT EA buffer\r\n",
  "Nbtn": " netbt.sys    - NetBT device string\r\n",
  "FLwl": " <unknown>    - waiting lock\r\n",
  "Nbtt": " netbt.sys    - NetBT MDL buffer\r\n",
  "Nbtu": " netbt.sys    - NetBT MDL buffer\r\n",
  "Nbtv": " netbt.sys    - NetBT WINS allocation\r\n",
  "LSbf": " srvnet.sys   -     SMB1 buffer descriptor or srvnet allocation\r\n",
  "SisF": " <unknown>    -         SIS per file object\r\n",
  "HcMp": " hcaport.sys - HCAPORT_TAG_MINIPORT\r\n",
  "NtTo": " ntfs.sys     -     DEVICE_MANAGE_DATA_SET_ATTRIBUTES NtfsFileOffloadLookasideList\r\n",
  "HcMr": " hcaport.sys - HCAPORT_TAG_REMOVE_LOCK\r\n",
  "WofG": " wof.sys      - Wof general allocation\r\n",
  "NtTf": " ntfs.sys     -     NTFS_DISK_FLUSH_CONTEXT           NtfsDiskFlushContextLookasideList\r\n",
  "NtTe": " ntfs.sys     -     NTFS Telemetry\r\n",
  "NtTc": " ntfs.sys     -     FILE_LEVEL_TRIM_CONTEXT\r\n",
  "Lrac": " <unknown>    -     ACL for redirector\r\n",
  "GFIC": " win32k.sys                           - GDITAG_FONT_INTENSITY_CORRECTION\r\n",
  "HcMa": " hcaport.sys - HCAPORT_TAG_MAD\r\n",
  "HcMc": " hcaport.sys - HCAPORT_TAG_MISC\r\n",
  "IBbf": " tcpip.sys    - IP BVT Buffers\r\n",
  "BIG ": " nt!mm        - Large session pool allocations (ntos\\ex\\pool.c)\r\n",
  "NtTr": " ntfs.sys     -     DEVICE_MANAGE_DATA_SET_ATTRIBUTES NtfsDeviceManageDataSetAttributesLookasideList\r\n",
  "ADPT": " acpipagr.sys - Processor Aggregator Driver\r\n",
  "PaeD": " <unknown>    - PAE top level directory allocation blocks\r\n",
  "RaSr": " storport.sys - RaidAllocateSrb storport!_SCSI_REQUEST_BLOCK\r\n",
  "Pstb": " nt!ps        - Process tables via EX handle.c\r\n",
  "NDam": " ndis.sys     -     NdisAllocateMemory\r\n",
  "NDan": " ndis.sys     -     adapter name\r\n",
  "Nbt0": " netbt.sys    - NetBT name address\r\n",
  "Nbt1": " netbt.sys    - NetBT name address\r\n",
  "Nbt2": " netbt.sys    - NetBT NetBIOS address\r\n",
  "Nbt4": " netbt.sys    - NetBT client list\r\n",
  "Nbt5": " netbt.sys    - NetBT client list\r\n",
  "Nbt6": " netbt.sys    - NetBT datagram\r\n",
  "NDar": " ndis.sys     - NDIS_TAG_ALLOCATED_RESOURCES\r\n",
  "Nbt8": " netbt.sys    - NetBT address list\r\n",
  "Nbt9": " netbt.sys    - NetBT temporary allocation\r\n",
  "Mdp": "  netio.sys    - Memory Descriptor Lists\r\n",
  "Txis": " ntfs.sys     - TXF_ISO_SNAPSHOT\r\n",
  "hSVD": " mrxdav.sys - Shared Heap Tag\r\n",
  "WmMR": " <unknown>    - Wmi MofResouce chunks\r\n",
  "DEds": " devolume.sys - Drive extender disk set: DEVolume!DEDiskSet\r\n",
  "DEdr": " devolume.sys - Drive extender device relations\r\n",
  "DEdu": " devolume.sys - Drive extender disk set message: DEVolume!DE_DISK_SET_MESSAGE\r\n",
  "DEdt": " devolume.sys - Drive extender disk message: DEVolume!DE_DISK_MESSAGE\r\n",
  "DEdv": " devolume.sys - Drive extender driver object: DEVolume!DEDriver\r\n",
  "DEdi": " devolume.sys - Drive extender disk: DEVolume!DEDisk\r\n",
  "SmKy": " mrxsmb.sys    - SMB compounding key\r\n",
  "DEdm": " devolume.sys - Drive extender disk mini chunk: DEVolume!DiskMiniChunk\r\n",
  "DEdn": " devolume.sys - Drive extender disk identification info: DEVolume!DiskIdentificationInfo\r\n",
  "DEda": " devolume.sys - Drive extender disk array: DEVolume!DEDisk *\r\n",
  "DEdc": " devolume.sys - Drive extender disk chunk: DEVolume!DiskChunk\r\n",
  "DEdb": " devolume.sys - Drive extender disk directory information\r\n",
  "DEdg": " devolume.sys - Drive extender disk globals: DEVolume!DEDiskGlobals\r\n",
  "DCyd": " win32kbase!DirectComposition::CSharedCompositionSpotLightMarshaler::_allocate            - DCOMPOSITIONTAG_SHAREDCOMPOSITIONSPOTLIGHTMARSHALER\r\n",
  "ArpM": " <unknown>    -     AtmArpS MARS structure\r\n",
  "ArpI": " <unknown>    -     AtmArpS Interface structure\r\n",
  "CpeK": " hal.dll      - HAL CMC Kernel Log\r\n",
  "ArpK": " <unknown>    -     AtmArpS ARP block\r\n",
  "CpeD": " hal.dll      - HAL CPE Driver Log\r\n",
  "Nwcs": " <unknown>    - Client Services for NetWare\r\n",
  "ArpA": " <unknown>    -     AtmArpS address\r\n",
  "ArpB": " <unknown>    -     AtmArpS buffer space\r\n",
  "SisB": " <unknown>    -         SIS per file object break event\r\n",
  "Txtr": " ntfs.sys     - TXF_TRANS (Txf transaction context)\r\n",
  "Pcop": " pacer.sys    - PACER Original Packet Contexts\r\n",
  "MsFc": " <unknown>    - Mailslot CCB, Client control block. Each client with an opened mailslot has one of these\r\n",
  "VDM ": " nt!vdm       - ntos\\vdm\r\n",
  "CpeT": " hal.dll      - HAL CPE temporary Log\r\n",
  "EQAn": " tcpip.sys    - EQoS application name\r\n",
  "CIsc": " ci.dll       - Code Integrity core dll\r\n",
  "ArpR": " <unknown>    -     AtmArpS NDIS request\r\n",
  "CcEv": " nt!cc        - Cache Manager Event\r\n",
  "rbRc": " <unknown>    - RedBook - Read completion context\r\n",
  "ArbR": " nt!arb       - ARBITER_RANGE_LIST_TAG\r\n",
  "SWid": " <unknown>    -         device ID\r\n",
  "WfpI": " netio.sys    - WFP index\r\n",
  "List": " <unknown>    -     kernel utilities list allocation\r\n",
  "FCwr": " dxgkrnl!CFlipWaitedConsumerReturn::operator new - FLIPCONTENT_WAITEDCONSUMERRETURN",
  "DCgb": " win32kbase!DirectComposition::CGdiBitmapMarshaler::_allocate                             - DCOMPOSITIONTAG_GDIBITMAPMARSHALER\r\n",
  "Arp?": " <unknown>    - ATM ARP server objects, atmarps.sys\r\n",
  "CMkb": " nt!cm        - registry key control blocks\r\n",
  "ArbA": " nt!arb       - ARBITER_ALLOCATION_STATE_TAG\r\n",
  "IPre": " tcpip.sys    - IP Reassembly buffers\r\n",
  "ArbM": " nt!arb       - ARBITER_MISC_TAG\r\n",
  "ArbL": " nt!arb       - ARBITER_ORDERING_LIST_TAG\r\n",
  "SWip": " <unknown>    -         POOLTAG_DEVICE_INTERFACEPATH\r\n",
  "IUDl": " <unknown>    -     Lookaside list allocations\r\n",
  "Usbm": " win32k!SetGestureConfigSettings      - USERTAG_BITMASK\r\n",
  "Vadl": " nt!mm        - Mm virtual address descriptors (long)\r\n",
  "SimB": " <unknown>    - Simbad (bad sector simulation driver) allocations\r\n",
  "WfpH": " netio.sys    - WFP hash\r\n",
  "SePa": " nt!se        - Process audit image names and captured policy structures\r\n",
  "Ssrl": " win32k.sys                           - GDITAG_SINGLEREADERLOCK\r\n",
  "WDMA": " <unknown>    - WDM Audio\r\n",
  "DCax": " win32kbase!DirectComposition::CAnalogExclusiveViewMarshaler::_allocate                   - DCOMPOSITIONTAG_ANALOGEXCLUSIVEVIEWMARSHALER\r\n",
  "p2cx": " perm2dll.dll - Permedia2 display driver - p2ctxt.c\r\n",
  "Dndt": " <unknown>    - Device node\r\n",
  "IoCc": " nt!io        - Io completion context\r\n",
  "DCfb": " win32kbase!DirectComposition::CTableTransferEffectMarshaler::SetBufferProperty           - DCOMPOSITIONTAG_FILTEREFFECTBUFFER\r\n",
  "ScLW": " classpnp.sys -      Power\r\n",
  "Usik": " win32k!InjectKeyboardInput           - USERTAG_INJECT_KEYBOARD\r\n",
  "PsWs": " nt!ps        - Process working set watch array\r\n",
  "ATac": " AppTag ATR command buffer\r\n",
  "SmEc": " mrxsmb10.sys    -      SMB1   echo buffer  (special build only)\r\n",
  "NLap": " tcpip.sys    - Network Layer Netio Helper Function allocations\r\n",
  "Usim": " win32k!InjectMouseInput              - USERTAG_INJECT_MOUSE\r\n",
  "smDa": " nt!store     -         ReadyBoost cache file DACL\r\n",
  "Usiq": " win23k!CInputQueueProp               - USERTAG_COMPOSITIONINPUTQUEUE\r\n",
  "Usip": " win32k!CreateNode                    - USERTAG_INPUTPOINTERNODE\r\n",
  "TcWS": " tcpip.sys    - TCP Window Scaling Diagnostics\r\n",
  "UCAM": " <unknown>    - USB digital camera library\r\n",
  "Usit": " win32k!InjectTouchInput              - USERTAG_INJECT_TOUCH\r\n",
  "VfUs": " nt!Vf        - Memory allocated by a call to IoSetCompletionRoutineEx.\r\n",
  "Prcr": " processr.sys - Processr driver allocations\r\n",
  "Usix": " win32k!AllocInputTransformEntry      - USERTAG_INPUT_TRANSFORM\r\n",
  "ScsL": " <unknown>    - non-pnp SCSI class.c driver allocations\r\n",
  "Fwpx": " fwpkclnt.sys - WFP NBL tagged context\r\n",
  "Fwpp": " fwpkclnt.sys - Windows Filtering Platform export driver.\r\n",
  "DCr3": " win32kbase!DirectComposition::CRotateTransform3DMarshaler::_allocate                     - DCOMPOSITIONTAG_ROTATETRANSFORM3DMARSHALER\r\n",
  "Err ": " <unknown>    - Error strings\r\n",
  "Fwpi": " fwpkclnt.sys - WFP injector info\r\n",
  "UlPL": " http.sys     - Pipeline\r\n",
  "Fwpn": " fwpkclnt.sys - WFP NBL info\r\n",
  "Fwpc": " fwpkclnt.sys - WFP injection call context\r\n",
  "AlVi": " nt!alpc      - ALPC view\r\n",
  "FlSB": " tcpip.sys    - Framing Layer Stack Block\r\n",
  "SrHB": " sr.sys       -         Hash bucket\r\n",
  "LBbr": " <unknown>    -     Become backup request\r\n",
  "LBbs": " <unknown>    -     Browser server\r\n",
  "Tdat": " <unknown>    - NB Data\r\n",
  "Woft": " wof.sys      - Wof transaction context\r\n",
  "LBbb": " <unknown>    -     Become backup context\r\n",
  "LBbl": " <unknown>    -     Backup List\r\n",
  "LBbn": " <unknown>    -     Name\r\n",
  "TcRL": " tcpip.sys    - TCP Create And Connect Tcb Rate Limit Pool\r\n",
  "CcSc": " nt!cc        - Cache Manager Shared Cache Map\r\n",
  "BlCc": " blkcache.sys - Block Cache Driver\r\n",
  "SBad": " <unknown>    - bad block simulator - simbad.c\r\n",
  "Uctd": " http.sys     - Response Tdi Buffer\r\n",
  "IPdc": " tcpip.sys    - IP Destination Cache\r\n",
  "DCrs": " win32kbase!DirectComposition::CSharedVisualReferenceControllerMarshaler::_allocate       - DCOMPOSITIONTAG_SHAREDVISUALREFERENCECONTROLLERMARSHALER\r\n",
  "DCrr": " win32kbase!DirectComposition::CSharedReadVisualReferenceMarshaler::_allocate             - DCOMPOSITIONTAG_SHAREDREADVISUALREFERENCEMARSHALER\r\n",
  "Gppt": " win32k!PROXYPORT::PROXYPORT          - GDITAG_PROXYPORT\r\n",
  "UlNO": " http.sys     - NSGO Pool\r\n",
  "DCrv": " win32kbase!DirectComposition::CRedirectVisualMarshaler::_allocate                        - DCOMPOSITIONTAG_REDIRECTVISUALMARSHALER\r\n",
  "UlNP": " http.sys     - Non-Paged Data\r\n",
  "Ghas": " win32k!FHMEMOBJ::FHMEMOBJ            - GDITAG_PFE_HASHTABLE\r\n",
  "PfTD": " nt!pf        - Pf Trace Dump\r\n",
  "Vk??": " vmbkmcl.sys  - Hyper-V VMBus KMCL driver\r\n",
  "CMUw": " nt!cm        - Configuration Manager Unit of Work Tag\r\n",
  "DCrc": " win32kbase!DirectComposition::CRectangleClipMarshaler::_allocate                         - DCOMPOSITIONTAG_RECTANGLECLIPMARSHALER\r\n",
  "fprd": " wof.sys      - Compressed file small read buffer\r\n",
  "IIpk": " <unknown>    - Packet\r\n",
  "DCrf": " win32kbase!DirectComposition::CVisualReferenceControllerMarshaler::_allocate             - DCOMPOSITIONTAG_VISUALREFERENCECONTROLLERMARSHALER\r\n",
  "VoSx": " volsnap.sys  -      Dispatch context allocations\r\n",
  "NDpk": " ndis.sys     - NDIS_TAG_PKT_PATTERN\r\n",
  "NDpn": " ndis.sys     - NDIS_TAG_PARAMETER_NODE\r\n",
  "NDpo": " ndis.sys     - NDIS_TAG_PORT\r\n",
  "NDpl": " ndis.sys     - NDIS_TAG_PERF_LOG_ID\r\n",
  "BT3C": " bt3c.sys     - Bluetooth 3COM minidriver\r\n",
  "NDpc": " ndis.sys     - NDIS_TAG_PROTOCOL_CONFIGURATION\r\n",
  "VoSr": " volsnap.sys  -      Device relations allocations\r\n",
  "TCPT": " <unknown>    - TCB pool\r\n",
  "NDpf": " ndis.sys     - NDIS_TAG_FILTER\r\n",
  "VmCc": " volmgrx.sys  - Configuration copies\r\n",
  "Tedd": " tcpip.sys    - TCP/IP Event Data Descriptors\r\n",
  "VoSh": " volsnap.sys  -      Bit history allocations\r\n",
  "VoSi": " volsnap.sys  -      Io status block allocations\r\n",
  "DCcm": " win32kbase!DirectComposition::CCompositionCubeMapMarshaler::_allocate                    - DCOMPOSITIONTAG_CUBEMAPMARSHALER\r\n",
  "VoSm": " volsnap.sys  -      Bitmap allocations\r\n",
  "VoSo": " volsnap.sys  -      Old heap entry allocations\r\n",
  "NDpr": " ndis.sys     - NDIS_TAG_PERIODIC_RECEIVES\r\n",
  "Cdpe": " cdfs.sys     - CDFS Prefix Entry\r\n",
  "NDpp": " ndis.sys     -     packet pool\r\n",
  "UdEW": " tcpip.sys    - UDP Endpoint Work Queue Contexts\r\n",
  "VmCr": " volmgrx.sys  - Completion routine contexts\r\n",
  "NDpw": " ndis.sys     - NDIS_TAG_WOL_PATTERN\r\n",
  "VmCp": " volmgrx.sys  - Copies\r\n",
  "TdCI": " tdx.sys      - TDX Connection Information\r\n",
  "VoSs": " volsnap.sys  -      Short term allocations\r\n",
  "PPTa": " <unknown>    - PPTP_SEND_DGRAMDESC_TAG\r\n",
  "Ul??": " http.sys     - tags. Note: In-use tags are of the form \"Ul??\" or \"Uc??\".and   Free tags are of the form \"uL??\" or \"uC??\";\r\n",
  "I4e": "  tcpip.sys    - IPv4 Echo data\r\n",
  "SmWi": " mrxsmb.sys    - SMB sequence window\r\n",
  "DCnb": " win32kbase!DirectComposition::CDeletedNotificationList::EnsureTagAllocation              - DCOMPOSITIONTAG_DELETEDNOTIFICATIONLISTBUFFER\r\n",
  "Tsmp": " tcpip.sys    - TCP Send Memory Descriptor Lists\r\n",
  "LSsf": " srv.sys      -     SMB1 BlockTypeDfs\r\n",
  "None": " <unknown>    - call to ExAllocatePool\r\n",
  "VubW": " vmusbbus.sys  - Virtual Machine USB Bus Driver (WDF)\r\n",
  "NDfa": " ndis.sys     - NDIS_TAG_FILTER_ADDR\r\n",
  "FtV ": " <unknown>    - Fault tolerance driver\r\n",
  "Cdcc": " cdfs.sys     - CDFS Ccb\r\n",
  "NDfb": " ndis.sys     - NDIS_TAG_LWFILTER_BLOCK\r\n",
  "CcZe": " nt!cc        - Cache Manager Buffer of Zeros\r\n",
  "NDfd": " ndis.sys     - NDIS_TAG_FILE_DESCRIPTOR\r\n",
  "Aml*": " <unknown>    - ACPI AMLI Pooltags\r\n",
  "GFld": " win32k.sys                           - GDITAG_FLOODFILL\r\n",
  "PPMi": " nt!po        - Processor Power Manager Idle States\r\n",
  "UndP": " <unknown>    - EXIFS Underlying Path\r\n",
  "FMlp": " fltmgr.sys   -       Paged stream list control entry structures\r\n",
  "LBpn": " <unknown>    -     Paged Name\r\n",
  "PfTt": " nt!pf        - Pf Translation tables\r\n",
  "UlLH": " http.sys     - Log File Handle\r\n",
  "TcRW": " tcpip.sys    - TCP Receive Window Tuning Blocks\r\n",
  "FMla": " fltmgr.sys   -       Per-processor IRPCTRL lookaside lists\r\n",
  "VmMm": " volmgrx.sys  - Mirror emergency mappings\r\n",
  "Mmlk": " nt!mm        - ProbeAndLock MDL tracker\r\n",
  "PcCi": " <unknown>    - WDM audio port class adapter device object stuff\r\n",
  "TC??": " TCP          - TCP/IP network protocol\r\n",
  "Acpt": " acpi.sys     - ACPI table data\r\n",
  "Lrfl": " <unknown>    -     Fcb Locks\r\n",
  "SRdm": " scsirdma.sys - Infiniband SRP driver\r\n",
  "TcFR": " tcpip.sys    - TCP FineRTT Buffers\r\n",
  "Lrfc": " <unknown>    -     File Control Blocks\r\n",
  "ViMm": " dxgkrnl.sys  - Video memory manager\r\n",
  "NDfm": " ndis.sys     - NDIS_TAG_FAKE_MAC\r\n",
  "Mapr": " <unknown>    - arc firmware registry routines\r\n",
  "SmBf": " mrxsmb.sys    - SMB exchange buffer\r\n",
  "Acpg": " acpi.sys     - ACPI GPE data\r\n",
  "LCam": " <unknown>    - WDM mini video capture driver for Logitech camera\r\n",
  "KrbC": " ksecdd.sys   - Kerberos Client package\r\n",
  "Lrfp": " <unknown>    -     Fcb Paging locks\r\n",
  "MmHi": " nt!mm        - Mm image entry - allocated per session\r\n",
  "Acpi": " acpi.sys     - ACPI generic data\r\n",
  "AcpT": " acpi.sys     - ACPI thermal data\r\n",
  "AcpD": " acpi.sys     - ACPI device data\r\n",
  "LSsd": " srv.sys      -     SMB1 BlockTypeShareSecurityDescriptor\r\n",
  "AcpP": " acpi.sys     - ACPI power data\r\n",
  "LSsc": " srv.sys      -     SMB1 search(core)\r\n",
  "AcpR": " acpi.sys     - ACPI resource data\r\n",
  "AcpS": " acpi.sys     - ACPI string data\r\n",
  "MmHn": " nt!mm        - Mm sessionwide address name string entry\r\n",
  "NDfi": " ndis.sys     - NDIS_TAG_FILE_IMAGE\r\n",
  "AcpX": " acpi.sys     - ACPI translation data\r\n",
  "AcpF": " acpi.sys     - ACPI interface data\r\n",
  "LSsh": " srv.sys      -     SMB1 share\r\n",
  "CLd*": " clusdflt.sys - Cluster disk filter driver\r\n",
  "MmHv": " nt!mm        - Mm sessionwide address entry\r\n",
  "AcpE": " acpi.sys     - ACPI embedded controller data\r\n",
  "MapP": " <unknown>    - PNP map\r\n",
  "LSsr": " srv.sys      -     SMB1 search\r\n",
  "LSss": " srv.sys      -     SMB1 session\r\n",
  "AcpB": " acpi.sys     - ACPI buffer data\r\n",
  "MStu": " refs.sys     - Minstore tree update filter\r\n",
  "AcpL": " acpi.sys     - ACPI lock data\r\n",
  "AcpM": " acpi.sys     - ACPI miscellaneous data\r\n",
  "AcpO": " acpi.sys     - ACPI object data\r\n",
  "AcpI": " acpi.sys     - ACPI irp data\r\n",
  "AcpA": " acpi.sys     - ACPI arbiter data\r\n",
  "RxWq": " rdbss.sys - RDBSS work queue\r\n",
  "IHaO": " tcpip.sys    - IPsec hash object\r\n",
  "LSsp": " srv.sys      -     SMB1 search(core complete)\r\n",
  "DCpr": " win32kbase!DirectComposition::CPrimitiveMarshaler::_allocate                             - DCOMPOSITIONTAG_PRIMITIVEMARSHALER\r\n",
  "ATMU": " atmuni.sys   - ATM UNI Call Manager\r\n",
  "Uswe": " win32k!_SetWinEventHook              - USERTAG_WINEVENT\r\n",
  "SrCo": " sr.sys       -         SR's control object\r\n",
  "ScMC": " <unknown>    -      medium changer allocations\r\n",
  "VmTe": " volmgrx.sys  - Table of contents entries\r\n",
  "AzCm": " HDAudio.sys  - HD Audio Class Driver (AzCommon)\r\n",
  "Usqq": " win32k!InitQMiPTrace                 - USERTAG_QMIPTRACE\r\n",
  "AzCd": " HDAudio.sys  - HD Audio Class Driver (CodecVendor)\r\n",
  "WmiA": " <unknown>    - Wmi ACPI mapper\r\n",
  "FLfl": " <unknown>    - exported (non-private) file lock\r\n",
  "Lrps": " <unknown>    -     Paged security entry\r\n",
  "Lrpt": " <unknown>    -     Primary transport server list\r\n",
  "DCpz": " win32kbase!DirectComposition::CParticleEmitterMarshaler::_allocate                       - DCOMPOSITIONTAG_PARTICLEEMITTERMARSHALER\r\n",
  "AzCE": " HDAudio.sys  - HD Audio Class Driver (CEAAudioRender)\r\n",
  "TSBV": " <unknown>    - WDM mini driver for Toshiba 750 capture\r\n",
  "CcBr": " nt!cc        - Cache Manager Bitmap range\r\n",
  "Pcfc": " pacer.sys    - PACER Filter Contexts\r\n",
  "KSai": " <unknown>    -    default allocator instance header\r\n",
  "KSah": " <unknown>    - Ks auxiliary stream headers\r\n",
  "CcBz": " nt!cc        - Cache Manager Bcb Zone\r\n",
  "CcBc": " nt!cc        - Cache Manager Bcb from pool\r\n",
  "Usjb": " win32k!CreateW32Job                  - USERTAG_W32JOB\r\n",
  "TmLo": " nt!tm        - Tm Log Entries\r\n",
  "Pfhc": " pacer.sys    - PACER File Handle Contexts\r\n",
  "CcBm": " nt!cc        - Cache Manager Bitmap\r\n",
  "CcBn": " nt!cc        - Cache Manager Bcb trim notification entry\r\n",
  "PfPB": " nt!pf        - Pf Pfn query buffers\r\n",
  "SDb ": " smbdirect.sys - SMB Direct adapter objects\r\n",
  "VoSb": " volsnap.sys  -      Buffer allocations\r\n",
  "mkup": " mpsdrv.sys   - MPSDRV upcall request\r\n",
  "VcMn": " rdpdr.sys - Dynamic Virtual manager object\r\n",
  "Vm??": " volmgrx.sys  - Volume Manager Extension\r\n",
  "Ucto": " http.sys     - Tdi Objects Pool\r\n",
  "UsWE": " win32k!ReportHungExplorerToWer       - USERTAG_WER\r\n",
  "FwSD": " tcpip.sys    - WFP security descriptor\r\n",
  "S3  ": " <unknown>    - S3 video driver\r\n",
  "UlBL": " http.sys     - Binary Log File Entry\r\n",
  "PX1 ": " <unknown>    - ndis ProviderEventLookaside\r\n",
  "Vi32": " dxgmms2.sys  - Video memory manager DMA buffer private data\r\n",
  "VoSc": " volsnap.sys  -      Snapshot context allocations\r\n",
  "Gpre": " win32k!pSpCreatePresent              - GDITAG_PRESENT\r\n",
  "DOPE": " <unknown>    - Device Object Power Extension (po component)\r\n",
  "Ic4h": " tcpip.sys    - ICMP IPv4 Headers\r\n",
  "Gdrv": " win32k!EngCreateClip                 - GDITAG_CLIPOBJ\r\n",
  "smCa": " nt!store     -         ReadyBoost cache\r\n",
  "PSHD": " pshed.dll    - PSHED\r\n",
  "TcPt": " tcpip.sys    - TCP Partitions\r\n",
  "WfTi": " <unknown>    - WFP timer\r\n",
  "UDNb": " tcpip.sys    - UDP NetBuffers\r\n",
  "DPwr": " nt!pnp       - PnP power management\r\n",
  "Ke  ": " <unknown>    - Kernel data structures\r\n",
  "Pnp3": " nt!pnp       - PNPMGR HW Profile\r\n",
  "Nbuf": " netio.sys    - NetIO Memory Descriptor List allocations\r\n",
  "MmVt": " nt!mm        - Verifier thunk allocations\r\n",
  "RxEc": " rdbss.sys - RDBSS ECP\r\n",
  "NDTr": " ndis.sys     - NDIS_TAG_TRANSFER_DATA\r\n",
  "MmVs": " nt!mm        - Mm virtual address descriptors short form (private views)\r\n",
  "WlPw": " writelog.sys - Writelog planned write\r\n",
  "VsRT": " vmswitch.sys - Virtual Machine Network Switch Driver (routing table)\r\n",
  "LSmi": " srv.sys      -     SMB1 BlockTypeMisc\r\n",
  "MmVd": " nt!mm        - Mm virtual address descriptors for mapped views\r\n",
  "LSmf": " srv.sys      -     SMB1 MFCB\r\n",
  "DCpl": " win32kbase!DirectComposition::PropertySetKernelModeAllocator::AllocateAndClear           - DCOMPOSITIONTAG_PROPERTYSETSTORAGE\r\n",
  "Iprc": " tcpip.sys    - IPsec RPC context\r\n",
  "NDrl": " ndis.sys     -     resource list\r\n",
  "CcPL": " nt!ccpf      - Prefetcher read list\r\n",
  "CcPM": " nt!ccpf      - Prefetcher metadata\r\n",
  "Ttnc": "  tcpip.sys   - WFP tunnel nexthop context\r\n",
  "NDPa": " ndis.sys     - Apple Talk\r\n",
  "CcPI": " nt!ccpf      - Prefetcher intermediate table\r\n",
  "CcPF": " nt!ccpf      - Prefetcher file name\r\n",
  "CcPD": " nt!ccpf      - Prefetcher trace dump\r\n",
  "CcPB": " nt!ccpf      - Prefetcher trace buffer\r\n",
  "CcPC": " nt!ccpf      - Prefetcher context\r\n",
  "RaCD": " storport.sys - RaUnitScsiGetDumpPointersIoctl\r\n",
  "CcPV": " nt!ccpf      - Prefetcher queried volumes\r\n",
  "CcPW": " nt!ccpf      - Prefetcher workers\r\n",
  "CcPT": " nt!ccpf      - Prefetcher trace\r\n",
  "DVCx": " <unknown>    - AsyncEngineContext, DAV MiniRedir\r\n",
  "CcPS": " nt!ccpf      - Prefetcher scenario\r\n",
  "LBci": " <unknown>    -     Connection info\r\n",
  "CcPn": " nt!ccpf      - Prefetcher name info\r\n",
  "Vi15": " dxgmms2.sys  - Video memory manager global state\r\n",
  "Vi16": " dxgmms2.sys  - Video memory manager command state\r\n",
  "UlAO": " http.sys     - App Pool Object\r\n",
  "Vi10": " dxgmms2.sys  - Video memory manager process heap\r\n",
  "Vi11": " dxgmms2.sys  - Video memory manager process heap block\r\n",
  "CcPh": " nt!ccpf      - Prefetcher header preallocation\r\n",
  "Vi13": " dxgmms2.sys  - Video memory manager process adapter info\r\n",
  "CcPf": " nt!ccpf      - Prefetcher\r\n",
  "WlBs": " writelog.sys - Writelog block store\r\n",
  "CMVa": " nt!cm        - value cache value tag\r\n",
  "Vi18": " dxgmms2.sys  - Video memory manager pool block\r\n",
  "CcPc": " nt!cc        - Cache Manager Private Cache Map\r\n",
  "UlAB": " http.sys     - Auxiliary Buffer\r\n",
  "CcPa": " nt!ccpf      - Prefetcher async context\r\n",
  "UsdD": " win32k!NtUserfnDDEINIT               - USERTAG_DDEd\r\n",
  "UlCY": " http.sys     - Connection Count Entry\r\n",
  "Dire": " <unknown>    - Directory objects\r\n",
  "PcFp": " <unknown>    - WDM audio stuff\r\n",
  "CcPv": " nt!ccpf      - Prefetcher volume info\r\n",
  "CcPw": " nt!ccpf      - Prefetcher enable worker\r\n",
  "Pcpc": " pacer.sys    - PACER Packet Contexts\r\n",
  "CcPs": " nt!ccpf      - Prefetcher section table\r\n",
  "CcPp": " nt!ccpf      - Prefetcher instructions\r\n",
  "CcPq": " nt!ccpf      - Prefetcher query buffer\r\n",
  "UcSp": " http.sys     - Sspi Pool\r\n",
  "WmiI": " <unknown>    - Wmi Instance Names\r\n",
  "HcPr": " hcaport.sys - HCAPORT_TAG_PROTD\r\n",
  "Usmt": " win32k!xxxMNAllocMenuState           - USERTAG_MENUSTATE\r\n",
  "IoNm": " nt!io        - Io parsing names\r\n",
  "Pcna": " pacer.sys    - PACER Filter Network Addresses\r\n",
  "PsIm": " nt!ps        - Thread impersonation (PS_IMPERSONATE_INFORMATION, pre-Vista)\r\n",
  "MSht": " refs.sys     - Minstore stack hash table\r\n",
  "VmLc": " volmgrx.sys  - Log copies\r\n",
  "PNI ": " <unknown>    - Power Notify Instance\r\n",
  "LBmh": " <unknown>    -     Mailslot header\r\n",
  "Pcnt": " pacer.sys    - PACER NetBufferTimes\r\n",
  "MSho": " refs.sys     - Minstore hash table overflow (incl. page tables)\r\n",
  "LBma": " <unknown>    -     Master announce context\r\n",
  "MSha": " refs.sys     - Minstore hash table (incl. page tables)\r\n",
  "Ucsc": " win32k!SetShellCursorClip            - USERTAG_SHELL_CURSOR_CLIP\r\n",
  "LBmb": " <unknown>    -     Mailslot Buffer\r\n",
  "Dun5": " <unknown>    - NT5 Universal printer driver\r\n",
  "Urdr": " win32k!SetRedirectionBitmap          - USERTAG_REDIRECT\r\n",
  "V2io": " vhdmp.sys    - VHD2 internal I/O allocation\r\n",
  "ParC": " <unknown>    - Parallel class driver\r\n",
  "AlCi": " tcpip.sys    -     ALE credential info\r\n",
  "VsDI": " vmswitch.sys - Virtual Machine Network Switch Driver (direct I/O NIC)\r\n",
  "FIou": " fileinfo.sys - FileInfo FS-filter User Open Context\r\n",
  "KNMI": " <unknown>    - Kernel NMI Callback object\r\n",
  "GTmp": " win32k!AllocFreeTmpBuffer            - GDITAG_TEMP_THREADLOCK\r\n",
  "ParV": " <unknown>    - ParVdm driver for vdm<->parallel port communciation\r\n",
  "SeAt": " nt!se        - Security Attributes\r\n",
  "Usmr": " win32k!SnapshotMonitorRects          - USERTAG_MONITORRECTS\r\n",
  "ParP": " <unknown>    - Parallel port driver\r\n",
  "FIof": " fileinfo.sys - FileInfo FS-filter File Object Context\r\n",
  "NDAa": " ndis.sys     - NDIS_PD_ASSOCIATION\r\n",
  "VmPs": " volmgrx.sys  - Arrays of packets\r\n",
  "FMos": " fltmgr.sys   -       Operation status ctrl structure\r\n",
  "AlCI": " nt!alpc      - ALPC communication info\r\n",
  "WSKs": " afd.sys      - WSK socket\r\n",
  "MmCa": " nt!mm        - Mm control areas for mapped files\r\n",
  "NDAm": " ndis.sys     - NDIS_PD_MEM_BLOCK NDIS_PD_SGL_BLOCK\r\n",
  "VmPa": " volmgrx.sys  - Packs\r\n",
  "VmPd": " volmgrx.sys  - Physical disks\r\n",
  "Usfl": " win32k!InitializeWin32KSyscallFilter - USERTAG_SERVICEFILTER\r\n",
  "NDAo": " ndis.sys     - NDIS_PD_CONFIG\r\n",
  "FMol": " fltmgr.sys   -       OPLOCK_CONTEXT structure\r\n",
  "Usjx": " win32k!JobCalloutAddProcess          - USERTAG_W32JOBEXTRA\r\n",
  "Gill": " win32kbase.sys                       - GDITAG_ISOLATED_LOOKASIDE_LIST\r\n",
  "TmPo": " nt!tm        - Tm Propagation Output\r\n",
  "NDAn": " ndis.sys     - NDIS_PD_COUNTER\r\n",
  "TmPi": " nt!tm        - Tm Protocol Information\r\n",
  "UsdA": " win32k!NewConversation               - USERTAG_DDEa\r\n",
  "PPT9": " <unknown>    - PPTP_SEND_ACKDATA_TAG\r\n",
  "IpHW": " ipsec.sys    -  hardware accleration items\r\n",
  "SmFc": " mrxsmb10.sys    -      SMB1   fsctl structures  (special build only)\r\n",
  "IpHU": " ipsec.sys    -  HUGHES headers in tunnel mode\r\n",
  "IpHT": " ipsec.sys    -  HUGHES headers in transport mode\r\n",
  "TmPa": " nt!tm        - Tm Propagate Argument\r\n",
  "TSwd": " rdpwd.sys    - RDPWD - Hydra Winstation Driver\r\n",
  "TmPb": " nt!tm        - Tm Propagation Buffer\r\n",
  "LS$S": " srv2.sys     -     SMB2 ecp\r\n",
  "Kse3": " ksecdd.sys   - Security driver allocs for sec package 3\r\n",
  "UlSl": " http.sys     - StringLog Buffer PoolTag\r\n",
  "TmPp": " nt!tm        - Tm Protocol Pointers\r\n",
  "TmPr": " nt!tm        - Tm Protocol\r\n",
  "DEir": " devolume.sys - Drive extender IRP based read request: DEVolume!IrpBasedReadRequest\r\n",
  "VmP2": " volmgrx.sys  - Large packets\r\n",
  "DEip": " devolume.sys - Drive extender IRP based logical to physical request: DEVolume!IrpBasedLogicalToPhysicalRequest\r\n",
  "VmP0": " volmgrx.sys  - Packets\r\n",
  "UsdB": " win32k!Createpxs                     - USERTAG_DDEb\r\n",
  "DEiw": " devolume.sys - Drive extender IRP based write request: DEVolume!IrpBasedWriteRequest\r\n",
  "UlSS": " http.sys     - Simple Status Item\r\n",
  "PfLB": " nt!pf        - Pf Log buffers\r\n",
  "Usmo": " win32k!_EnableIAMAccess              - USERTAG_MOSH\r\n",
  "DEic": " devolume.sys - Drive extender filter instance context\r\n",
  "UlSO": " http.sys     - Site Counter Entry\r\n",
  "UlSL": " http.sys     - StringLog PoolTag\r\n",
  "NDAq": " ndis.sys     - NDIS_PD_PLATFORM_QUEUE\r\n",
  "smHB": " rdyboost.sys -         ReadyBoost Hybrid Drive command buffer\r\n",
  "MmCl": " nt!mm        - Mm fork clone prototype PTEs\r\n",
  "Pdcs": " pdc.sys      - PDC_SCENARIO_TAG\r\n",
  "Cdtc": " cdfs.sys     - CDFS TOC\r\n",
  "UlHT": " http.sys     - Hash Table\r\n",
  "DCm3": " win32kbase!DirectComposition::CMatrixTransform3DMarshaler::_allocate                     - DCOMPOSITIONTAG_MATRIXTRANSFORM3DMARSHALER\r\n",
  "NSIk": " nsi.dll      - NSI RPC Tansactions\r\n",
  "Nb??": " <unknown>    - NetBT allocations\r\n",
  "NSIr": " nsi.dll      - NSI Generic Buffers\r\n",
  "RxTl": " rdbss.sys - RDBSS toplevel IRP\r\n",
  "TcDN": " tcpip.sys    - TCP Delayed Delivery Network Buffer Lists\r\n",
  "Fltt": " nt!Vf        - Log of Driver Verifier fault injection stack traces.\r\n",
  "P3D?": " perm3dd.dll  - Permedia3 display driver - DirectDraw/3D\r\n",
  "TSdd": " rdpdd.sys    - RDPDD - Hydra Display Driver\r\n",
  "DClv": " win32kbase!DirectComposition::CLayerVisualMarshaler::_allocate                           - DCOMPOSITIONTAG_LAYERVISUALMARSHALER\r\n",
  "SeAo": " nt!se        - Security Attributes and Operations\r\n",
  "Nf??": " nfssvr.sys   - NFS (Network File System) allocations\r\n",
  "CdPn": " cdfs.sys     - CDFS CdName in path entry\r\n",
  "Usd4": " win32k!AddPublicObject               - USERTAG_DDE4\r\n",
  "Usd5": " win32k!xxxCsEvent                    - USERTAG_DDE5\r\n",
  "Usd6": " win32k!xxxCsEvent                    - USERTAG_DDE6\r\n",
  "Usd7": " win32k!xxxCsEvent                    - USERTAG_DDE7\r\n",
  "FCrs": " dxgkrnl!CContentResourceState::operator new - FLIPCONTENT_CONTENTRESOURCESTATE\r\n",
  "NulI": " tlnull.sys   - Null TL Indications\r\n",
  "Usd2": " win32k!_DdeSetQualityOfService       - USERTAG_DDE2\r\n",
  "AlMs": " nt!alpc      - ALPC message\r\n",
  "SrFE": " sr.sys       -         File information buffer\r\n",
  "Usd8": " win32k!xxxMessageEvent               - USERTAG_DDE8\r\n",
  "Usd9": " win32k!xxxCsDdeInitialize            - USERTAG_DDE9\r\n",
  "NDqu": " ndis.sys     - NDIS_TAG_QUEUE\r\n",
  "UsdE": " win32k!xxxClientCopyDDEIn1           - USERTAG_DDE\r\n",
  "VmBl": " volmgrx.sys  - Raw configuration blocks\r\n",
  "NDqs": " ndis.sys     - NDIS_TAG_QOS\r\n",
  "Usml": " win32k!MsgLookupTableAlloc           - USERTAG_MESSAGE_FILTER\r\n",
  "DNSk": " netio.sys    - DNS RPC Transactions\r\n",
  "PcwT": " nt!pcw       - PCW Temporary (short-lived) buffer\r\n",
  "SrPC": " sr.sys       -         Persistant configuration information\r\n",
  "NDqo": " ndis.sys     - NDIS_TAG_QUERY_OBJECT_WORKITEM\r\n",
  "VmBu": " volmgrx.sys  - I/O buffers\r\n",
  "Tnbl": " <unknown>    - NB Lists\r\n",
  "DCik": " win32kbase!DirectComposition::CInkMarshaler::_allocate                                   - DCOMPOSITIONTAG_INKMARSHALER\r\n",
  "Usdc": " win32k!CreateCacheDC                 - USERTAG_DCE\r\n",
  "SmPi": " mrxsmb10.sys    -      SMB1   pipeinfo buffer (special build only)\r\n",
  "DCic": " win32kbase!DirectComposition::CInteractionConfigurationGroup::_allocate                  - DCOMPOSITIONTAG_INTERACTIONCONFIGURATIONGROUP\r\n",
  "Usdi": " win32k!CreateMonitor                 - USERTAG_DISPLAYINFO\r\n",
  "Usdv": " win32k!NtUserfnINDEVICECHANGE        - USERTAG_DEVICECHANGE\r\n",
  "Usdw": " win32k!GetProductString              - USERTAG_DEVICENAME\r\n",
  "Usdp": " win32k!NtUserDelegateCapturePointers - USERTAG_DELEGATEPOINTERSTRUCT\r\n",
  "Usds": " win32k!xxxDragObject                 - USERTAG_DRAGDROP\r\n",
  "DCir": " win32kbase!DirectComposition::CInteractionTrackerMarshaler::_allocate                    - DCOMPOSITIONTAG_INTERACTIONTRACKERMARSHALER\r\n",
  "SrFN": " sr.sys       -         File name\r\n",
  "DCit": " win32kbase!DirectComposition::CInteractionMarshaler::EnsureTouchConfigurationList        - DCOMPOSITIONTAG_INTERACTIONTOUCHCONFIGURATION\r\n",
  "Usdz": " win32kbase!DelayZonePalmRejection::_AddDelayZoneToListInternal   - USERTAG_DELAYZONEINFO\r\n",
  "RxM9": " rdbss.sys - RDBSS cloned unicode string\r\n",
  "PsFn": " nt!ps        - Captured image file name buffer (temporary allocation)\r\n",
  "ScsH": " <unknown>    - non-pnp SCSI from class.h (class2)\r\n",
  "InWP": " tcpip.sys    - Inet Wake Port Record\r\n",
  "TcSa": " tcpip.sys    - TCP Sack Data\r\n",
  "SmFi": " mrxsmb.sys    - SMB file\r\n",
  "CopW": " <unknown>    - EXIFS CopyOnWrite\r\n",
  "FSrN": " nt!fsrtl     - File System Run Time\r\n",
  "DwmL": " win32k!HwndLookupAllocTableData      - GDITAG_DWM_HWND_LOOKUP\r\n",
  "FSrt": " nt!fsrtl     - File System Run Time allocations (DO NOT USE!)\r\n",
  "FSrs": " nt!fsrtl     - File System Run Time Work Item for low-stack posting\r\n",
  "MmWw": " nt!mm        - Write watch VAD info\r\n",
  "Dvg6": " <unknown>    - vga 64K color video driver\r\n",
  "Ipur": " tcpip.sys    - IP Unicast Routes\r\n",
  "rbMp": " <unknown>    - RedBook - Mdl pointer block\r\n",
  "MmWs": " nt!mm        - PTE flush list for working set operations\r\n",
  "Dvg2": " <unknown>    - vga 256 color video driver\r\n",
  "Wl2n": " wfplwfs.sys  - WFP L2 NBL context\r\n",
  "FSrd": " nt!fsrtl     - File System Run Time\r\n",
  "AECi": " <unknown>    - filter object interface for MS acoustic echo canceller\r\n",
  "UlTT": " http.sys     - Thread Tracker\r\n",
  "FSro": " nt!fsrtl     - File System Run Time\r\n",
  "LSlf": " srv.sys      -     SMB1 LFCB\r\n",
  "FSrm": " nt!fsrtl     - File System Run Time\r\n",
  "TcSR": " tcpip.sys    - TCP Send Requests\r\n",
  "LSlb": " srv2.sys     -     SRVLIB security descriptor/registry buffer\r\n",
  "Fsb": "  netio.sys    - Fixed-Size Block pool\r\n",
  "DCio": " win32kbase!DirectComposition::CInteractionMarshaler::_allocate                           - DCOMPOSITIONTAG_INTERACTIONMARSHALER\r\n",
  "wpcf": " wof.sys      - Wim config file\r\n",
  "AtD ": " <unknown>    - atdisk.c\r\n",
  "Dtga": " <unknown>    - tga video driver\r\n",
  "OHCI": " <unknown>    - Open Host Controller Interface for USB\r\n",
  "p2su": " perm2dll.dll - Permedia2 display driver - ddsurf.c\r\n",
  "AzPx": " HDAudio.sys  - HD Audio Class Driver (AzPower)\r\n",
  "Qpci": " <unknown>    -      CfInfo\r\n",
  "ObHd": " nt!ob        - object handle count data base\r\n",
  "InIS": " tcpip.sys    - Inet Inspect Streams\r\n",
  "Qpcb": " <unknown>    -      ClassificationBlock\r\n",
  "HcOb": " hcaport.sys - HCAPORT_TAG_OBJECT\r\n",
  "Qpcd": " <unknown>    -      CfInfoData\r\n",
  "Usmg": " win32k!Magxxx                        - USERTAG_MAGNIFICATION\r\n",
  "Null": " tlnull.sys   - Null TL Generics\r\n",
  "LXMK": " <unknown>    - kernel mixer line driver (KMXL - looks like they got their tag backwards)\r\n",
  "MmId": " nt!mm        - PFN identity buffer for setting PFN priorities\r\n",
  "VmLa": " volmgrx.sys  - Drive layouts\r\n",
  "LSrf": " srv.sys      -     SMB1 RFCB\r\n",
  "VmLo": " volmgrx.sys  - Logs\r\n",
  "MmIh": " nt!mm        - Image header allocation for Se validation\r\n",
  "MmIm": " nt!mm        - IO space MDL trackers\r\n",
  "Dvgr": " <unknown>    - vga for risc video driver\r\n",
  "MmIo": " nt!mm        - IO space mapping trackers\r\n",
  "MmIn": " nt!mm        - Mm inpaged io structures\r\n",
  "LSrp": " srvnet.sys   -     srvnet RPC allocation\r\n",
  "WmiN": " <unknown>    - Wmi Notification Notification Packet\r\n",
  "PsTf": " nt!ps        - Job object token filter\r\n",
  "Dvga": " <unknown>    - vga 16 color video driver\r\n",
  "DCia": " win32kbase!DirectComposition::CInjectionAnimationMarshaler::_allocate                    - DCOMPOSITIONTAG_INJECTIONANIMATIONMARSHALER\r\n",
  "UsIa": " win32k!NSInstrumentation::CReferenceTracker::CReferenceCountedType::Create   - USERTAG_REFERENCE_COUNTED_TYPE_HANDLE\r\n",
  "@GMM": " <unknown>    - (Intel video driver) Memory manager\r\n",
  "IoOp": " nt!io        - I/O subsystem open packet\r\n",
  "Scs$": " <unknown>    - Tag for pnp class driver's SRB lookaside list\r\n",
  "Wl2f": " wfplwfs.sys  - WFP L2 flow\r\n",
  "NBSe": " <unknown>    -     EA buffer\r\n",
  "smPm": " rdyboost.sys -         ReadyBoost persist partial MDL buffer\r\n",
  "NBSf": " <unknown>    -     FCB\r\n",
  "NBSa": " <unknown>    -     address block\r\n",
  "NBSc": " <unknown>    -     connection block\r\n",
  "DVRw": " <unknown>    - ReadWrite, DAV MiniRedir\r\n",
  "DCda": " win32kbase!DirectComposition::CDCompDynamicArray::_allocate                              - DCOMPOSITIONTAG_DYNAMICARRAY\r\n",
  "NBSl": " <unknown>    -     LANA block\r\n",
  "NBSn": " <unknown>    -     copy of user NCB\r\n",
  "Sr??": " sr.sys       - System Restore file system filter driver\r\n",
  "Vi0a": " dxgmms2.sys  - Video memory manager global alloc VGPU\r\n",
  "NBSr": " <unknown>    -     registry allocations\r\n",
  "Vepp": " nt!Vf        - Verifier Pool Tracking information\r\n",
  "NBSy": " <unknown>    -     NetBIOS address (connect block)\r\n",
  "NBSx": " <unknown>    -     XNS NETONE address (connect block)\r\n",
  "NBSz": " <unknown>    -     NetBIOS address (listen block)\r\n",
  "PfFh": " nt!pf        - Pf Prefetch file handle cache array\r\n",
  "Azfg": " HDAudio.sys  - HD Audio Class Driver (datastore: function group)\r\n",
  "VcFl": " rdpdr.sys - Dynamic Virtual file object\r\n",
  "UlUL": " http.sys     - URL\r\n",
  "D3Dd": " <unknown>    - DX D3D driver (embedded in a display driver like s3mvirge.dll)\r\n",
  "I4ua": " tcpip.sys    - IPv4 Local Unicast Addresses\r\n",
  "Sect": " <unknown>    - Section objects\r\n",
  "WimF": " wimfsf.sys   - WIM Boot Filter\r\n",
  "DCex": " win32kbase!DirectComposition::CExpressionMarshaler::_allocate                            - DCOMPOSITIONTAG_EXPRESSIONMARSHALER\r\n",
  "KSnv": " <unknown>    -    registry name value\r\n",
  "DCyc": " win32kbase!DirectComposition::CSharedCompositionPointLightMarshaler::_allocate           - DCOMPOSITIONTAG_SHAREDCOMPOSITIONPOINTLIGHTMARSHALER\r\n",
  "XWan": " <unknown>    - ndis\\usrwan allocations\r\n",
  "KSns": " <unknown>    -    null security object\r\n",
  "Vi07": " dxgmms2.sys  - Video memory manager segment range\r\n",
  "Vi06": " dxgmms2.sys  - Video memory manager segment\r\n",
  "Pcge": " pacer.sys    - PACER Generic Buffers (DACL, SID allocations)\r\n",
  "Vi03": " dxgmms2.sys  - Video memory manager alloc\r\n",
  "NBS ": " <unknown>    - general NetBIOS allocations\r\n",
  "Vi01": " dxgmms2.sys  - Video memory manager global alloc\r\n",
  "PNCH": " <unknown>    - Power Notify Channel\r\n",
  "VmLr": " volmgrx.sys  - Log raw content\r\n",
  "Vi09": " dxgmms2.sys  - Video memory manager process\r\n",
  "Vi08": " dxgmms2.sys  - Video memory manager device\r\n",
  "ScsC": " <unknown>    - non-pnp SCSI CdRom\r\n",
  "RaPM": " tcpip.sys    - Raw Socket Partial Memory Descriptor List Tag\r\n",
  "ScsD": " <unknown>    - non-pnp SCSI Disk\r\n",
  "AtvE": " cea_km.lib   - Event broker aggregation library.\r\n",
  "ScsI": " <unknown>    - non-pnp SCSI port internal\r\n",
  "gEdg": " win32k!bTriangleMesh                 - GDITAG_TRIANGLEDATA\r\n",
  "PlMp": " storport.sys - PortpReadDriverParameterEntry\r\n",
  "V2sm": " vhdmp.sys    - VHD2 core allocation\r\n",
  "SeOT": " nt!se        - Security Learning Mode Object Type\r\n",
  "DCvi": " win32kbase!DirectComposition::CVisualMarshaler::_allocate                                - DCOMPOSITIONTAG_VISUALMARSHALER\r\n",
  "VssB": " vmswitch.sys - Virtual Machine Network Switch Driver (balance)\r\n",
  "Vi61": " dxgmms2.sys  - Video memory manager context alloc\r\n",
  "AlPU": " tcpip.sys    -     ALE secure socket policy update\r\n",
  "AlPT": " tcpip.sys    -     ALE peer target\r\n",
  "DCep": " win32kbase!DirectComposition::CCompiledEffectPropertyBag::_allocate                      - DCOMPOSITIONTAG_COMPILEDEFFECTPROPERTYBAGMARSHALER\r\n",
  "Uskb": " win32k!xxxLoadKeyboardLayoutEx       - USERTAG_KBDLAYOUT\r\n",
  "Uske": " win32k!GetKbdExId                    - USERTAG_KBDEXID\r\n",
  "OvfL": " <unknown>    - EXIFS FCBOVF List\r\n",
  "CMAl": " nt!cm        - internal registry memory allocator pool tag\r\n",
  "AlPF": " tcpip.sys    -     ALE policy filters\r\n",
  "UHUB": " <unknown>    - Universal Serial Bus Hub\r\n",
  "Usks": " win32k!PostUpdateKeyStateEvent       - USERTAG_KBDSTATE\r\n",
  "SeON": " nt!se        - Security Learning Mode Object Name\r\n",
  "SeOI": " nt!se        - Security Learning Mode Object Information\r\n",
  "Uskt": " win32k!ReadLayoutFile                - USERTAG_KBDTABLE\r\n",
  "IpKE": " ipsec.sys    -  keys\r\n",
  "SeOt": " nt!se        - Captured object type array, used by access check\r\n",
  "Vi60": " dxgmms2.sys  - Video memory manager cross adapter data\r\n",
  "SeOp": " nt!se        - Security Operation\r\n",
  "Vrdi": " netvsc60.sys - Virtual Machine Network VSC Driver (NDIS 6, RNDIS miniport driver library, chimney initiate offload)\r\n",
  "Cdsp": " cdfs.sys     - CDFS Buffer for spanning path table\r\n",
  "SeLS": " nt!se        - Security Logon Session tracking array\r\n",
  "smSt": " nt!store or rdyboost.sys - ReadyBoost various store allocations\r\n",
  "DamK": " dam.sys      - Desktop Activity Moderator\r\n",
  "Vsvq": " vmswitch.sys - Virtual Machine Network Switch Driver (VMQ)\r\n",
  "VMdl": " nt!Vf        - MDL allocated by I/O verifier version of IoAllocateMdl\r\n",
  "SeSA": " nt!se        - Security CAPE Staged Access Array\r\n",
  "PfMP": " nt!pf        - Pf Prefetch metadata buffers\r\n",
  "AlPi": " tcpip.sys    -     ALE peer info\r\n",
  "SeOn": " nt!se        - Security Captured Object Name information\r\n",
  "PCol": " nt!po        - Thermal cooling requests and extensions\r\n",
  "KsoO": " <unknown>    -    WDM audio stuff\r\n",
  "CMWT": " wibcm.sys - WIBCM_TIMER_TAG\r\n",
  "ZsaB": " <unknown>    - EXIFS ZeroBlock\r\n",
  "EQUn": " tcpip.sys    - EQoS uQoS NPI client data\r\n",
  "fppm": " wof.sys      - Compressed file IO parameters\r\n",
  "DEva": " devolume.sys - Drive extender volume chunk array: DEVolume!AutoVolumeChunkPtr *\r\n",
  "CMA3": " nt!cm        - Configuration Manager Audit Tag 3\r\n",
  "CMA2": " nt!cm        - Configuration Manager Audit Tag 2\r\n",
  "CMA1": " nt!cm        - Configuration Manager Audit Tag 1\r\n",
  "CMA4": " nt!cm        - Configuration Manager Audit Tag 4\r\n",
  "EQUp": " tcpip.sys    - EQoS URL policy section\r\n",
  "EQUr": " tcpip.sys    - EQoS URL string\r\n",
  "PPTb": " <unknown>    - PPTP_TDICLTS_TAG\r\n",
  "CMWK": " wibcm.sys - WIBCM_WORK_TAG\r\n",
  "Io  ": " nt!io        - general IO allocations\r\n",
  "PPTc": " <unknown>    - PPTP_RECV_CTRLDESC_TAG\r\n",
  "AlP6": " tcpip.sys    -     ALE peer IPv6 address\r\n",
  "Dump": " <unknown>    - Bugcheck dump allocations\r\n",
  "AlP4": " tcpip.sys    -     ALE peer IPv4 address\r\n",
  "Ic4c": " tcpip.sys    - ICMP IPv4 Control data\r\n",
  "PPTf": " <unknown>    - PPTP_RECV_DGRAMDATA_TAG\r\n",
  "IPfg": " tcpip.sys    - IP Fragment Groups\r\n",
  "EQUQ": " tcpip.sys    - UQoS generic allocation\r\n",
  "PPTg": " <unknown>    - PPTP_RECVDESC_TAG\r\n",
  "Udfa": " udfs.sys     - Udfs AD buffer\r\n",
  "McaC": " hal.dll      - HAL MCA corrected Log\r\n",
  "Udfc": " udfs.sys     - Udfs IRP context\r\n",
  "Udfb": " udfs.sys     - Udfs IO buffer\r\n",
  "Udfe": " udfs.sys     - Udfs enumeration match expression\r\n",
  "AzSi": " HDAudio.sys  - HD Audio Class Driver (SpdifIn)\r\n",
  "SrST": " sr.sys       -         Stream data information\r\n",
  "Sdba": " <unknown>    - Application compatibility Sdb* allocations\r\n",
  "AzSd": " HDAudio.sys  - HD Audio Class Driver (subdevicegraph)\r\n",
  "Usms": " win32k!xxxMoveSize                   - USERTAG_MOVESIZE\r\n",
  "NDio": " ndis.sys     - NDIS_TAG_IOV - IO Virtualization\r\n",
  "Mmxx": " nt!mm        - Mm temporary allocations\r\n",
  "Udfn": " udfs.sys     - Udfs Nonpaged Scb\r\n",
  "SrSC": " sr.sys       -         Stream contexts\r\n",
  "Udfs": " udfs.sys     - Udfs Sparing Mcb\r\n",
  "SmQP": " mrxsmb10.sys    -      SMB1   params for directory query transact  (special build only)\r\n",
  "Udft": " udfs.sys     - Udfs CDROM TOC\r\n",
  "SrSD": " sr.sys       -         Security data information\r\n",
  "Udfv": " udfs.sys     - Udfs Vpb\r\n",
  "AzSt": " HDAudio.sys  - HD Audio Class Driver (AzWaveCyclicStream, HdaWaveRTstream)\r\n",
  "Udfx": " udfs.sys     - Udfs Ccb\r\n",
  "Usmp": " win32k!AllocMousePromotionEntry      - USERTAG_MOUSEPROMOTIONENTRY\r\n",
  "NDvm": " ndis.sys     - NDIS_TAG_ALLOC_MEM_VERIFY_ON\r\n",
  "Gfid": " win32k.sys                           - GDITAG_UNIVERSAL_FONT_ID\r\n",
  "UdfC": " udfs.sys     - Udfs CRC table\r\n",
  "UdfB": " udfs.sys     - Udfs dynamic name buffer\r\n",
  "UdfD": " udfs.sys     - Udfs FID buffer for view spanning\r\n",
  "DChm": " win32kbase!DirectComposition::CHolographicExclusiveModeMarshaler::_allocate              - DCOMPOSITIONTAG_HOLOGRAPHICEXCLUSIVEMODEMARSHALER\r\n",
  "UdfF": " udfs.sys     - Udfs nonpaged Fcb\r\n",
  "UdfI": " udfs.sys     - Udfs IO context\r\n",
  "DChb": " win32kbase!DirectComposition::CHwndBitmapMarshaler::_allocate                            - DCOMPOSITIONTAG_HWNDBITMAPMARSHALER\r\n",
  "TCPY": " <unknown>    - SYN-TCB pool\r\n",
  "MmSd": " nt!mm        - extended subsections used to map data files\r\n",
  "UdfL": " udfs.sys     - Udfs IRP context lite (delayed close)\r\n",
  "DChe": " win32kbase!DirectComposition::CHolographicExclusiveViewMarshaler::_allocate              - DCOMPOSITIONTAG_HOLOGRAPHICEXCLUSIVEVIEWMARSHALER\r\n",
  "TSch": " rdpwd.sys    - RDPWD - Hydra char conversion\r\n",
  "VSt ": " storvsp.sys - Virtual Machine Storage VSP Driver\r\n",
  "UdfS": " udfs.sys     - Udfs short file name\r\n",
  "PcwQ": " nt!pcw       - PCW Query item\r\n",
  "UdfT": " udfs.sys     - Udfs generic table entry\r\n",
  "UdfV": " udfs.sys     - Udfs VMCB dirty sector bitmap\r\n",
  "SCB8": " <unknown>    -  Bull CP8 Transac serial reader\r\n",
  "NLuh": " <unknown>    - Network Layer Ul Handles\r\n",
  "TtCo": " <unknown>    - TTCP Connections\r\n",
  "MdlP": " <unknown>    - MDL per processor lookaside list pointers\r\n",
  "DChv": " win32kbase!DirectComposition::CHostVisualMarshaler::_allocate                            - DCOMPOSITIONTAG_HOSTVISUALMARSHALER\r\n",
  "Usex": " win32k!IsDeviceExcluded              - USERTAG_EXCLUDEDLIST\r\n",
  "UlRE": " http.sys     - Request Body Buffer\r\n",
  "TcPC": " tcpip.sys    - TCP Listener Pending Connections\r\n",
  "LeoC": " <unknown>    -     Symantec/Norton AntiVirus filter driver\r\n",
  "Nb08": " netbt.sys    - NetBT domain address list\r\n",
  "Nb09": " netbt.sys    - NetBT domain name\r\n",
  "VStW": " storvsp.sys - Virtual Machine Storage VSP Driver (WDF)\r\n",
  "UlRB": " http.sys     - Receive Buffer\r\n",
  "Nb04": " netbt.sys    - NetBT failed address list\r\n",
  "Nb05": " netbt.sys    - NetBT client element\r\n",
  "Nb06": " netbt.sys    - NetBT general buffer allocation\r\n",
  "Mdl ": " <unknown>    - Io, Mdls\r\n",
  "Nb01": " netbt.sys    - NetBT hash table\r\n",
  "Nb02": " netbt.sys    - NetBT remote name address cache\r\n",
  "Nb03": " netbt.sys    - NetBT remote name address cache\r\n",
  "Udf1": " udfs.sys     - Udfs file set descriptor buffer\r\n",
  "P3G?": " perm3dd.dll  - Permedia3 display driver\r\n",
  "Udf3": " udfs.sys     - Udfs volume descriptor sequence descriptor buffer\r\n",
  "Udf2": " udfs.sys     - Udfs volmume recognition sequence descriptor buffer\r\n",
  "TMte": " dxgkrnl!CTokenManager::TokenQueueTableEntry::Allocate - TOKENMANAGER_TOKENQUEUETABLEENTRY\r\n",
  "PcSt": " <unknown>    - WDM audio stuff\r\n",
  "FtT ": " <unknown>    - Fault tolerance driver\r\n",
  "UlRR": " http.sys     - Request Buffer References\r\n",
  "FCcm": " dxgkrnl!CFlipConsumerMessage::operator new - FLIPCONTENT_CONSUMERMESSAGE\r\n",
  "FMib": " fltmgr.sys   -       Irp SYSTEM buffers\r\n",
  "NEEB": " newt_ndis6.sys - NEWT Emulation Bench\r\n",
  "PRTM": " nt!po        - Power runtime management\r\n",
  "VStp": " storvsp.sys - Virtual Machine Storage VSP Driver (parser)\r\n",
  "Ushc": " win32k!AllocateHidConfigDesc         - USERTAG_HIDCONFIG\r\n",
  "VStr": " nt!Vf        - String buffer allocated by the Driver Verifier version of Rtl String APIs\r\n",
  "VStu": " storvsp.sys - Virtual Machine Storage VSP Driver (authentication)\r\n",
  "NDas": " ndis.sys     - NDIS_TAG_ALLOC_SHARED_MEM_ASYNC\r\n",
  "WvPc": " <unknown>    - WDM Audio WavePCI port\r\n",
  "LBvb": " <unknown>    -     View buffer\r\n",
  "PNCL": " <unknown>    - Power Notify channel list\r\n",
  "RtlT": " nt!rtl       - Temporary RTL allocation\r\n",
  "ScSB": " cdrom.sys    -      Scratch buffer (usually 64k)\r\n",
  "VStb": " storvsp.sys - Virtual Machine Storage VSP Driver (balance)\r\n",
  "VStd": " storvsp.sys - Virtual Machine Storage VSP Driver (device)\r\n",
  "FMng": " fltmgr.sys   -       NAME_GENERATION_CONTEXT structure\r\n",
  "Key ": " <unknown>    - Key objects\r\n",
  "DCat": " win32kbase!DirectComposition::CAnimationTriggerMarshaler::_allocate                      - DCOMPOSITIONTAG_ANIMATIONTRIGGERMARSHALER\r\n",
  "Inlc": " tcpip.sys    - IPsec NL complete context\r\n",
  "Lrdu": " <unknown>    -     Duplicated unicode string\r\n",
  "VNod": " nt!Vf        - Deadlock Verifier nodes\r\n",
  "Lrds": " <unknown>    -     Duplicated ansi string\r\n",
  "OlmI": " tcpip.sys    - Offload Manager Interfaces\r\n",
  "Lbuf": " <unknown>    - EXIFS Large Buffer\r\n",
  "OlmC": " tcpip.sys    - Offload Manager Connections\r\n",
  "Acrc": " tcpip.sys    -     ALE connect request inspection context\r\n",
  "NMRc": " tcpip.sys    - Network Module Registrar Arrays\r\n",
  "NMRb": " tcpip.sys    - Network Module Registrar Bindings\r\n",
  "MScs": " refs.sys     - Minstore read cache sync set\r\n",
  "NMRf": " tcpip.sys    - Network Module Registrar Filters\r\n",
  "Lrdn": " <unknown>    -     Domain Name\r\n",
  "Ustp": " win32k!FindOrCreateHoldingFrameForDevice   - USERTAG_TOUCHPADSTATE\r\n",
  "NMRm": " tcpip.sys    - Network Module Registrar Modules\r\n",
  "Acrl": " tcpip.sys    -     ALE connect redirect layer data\r\n",
  "NMRn": " tcpip.sys    - Network Module Registrar Network Protocol Identifiers\r\n",
  "MmFl": " nt!mm        - MDLs for large clusters for flushes\r\n",
  "NDdl": " ndis.sys     - NDIS_TAG_DBG_L\r\n",
  "GDcs": " win32k!GreDwmStartup                 - GDITAG_DWMSTATE\r\n",
  "Ucrp": " http.sys     - Response App Buffer\r\n",
  "NDdi": " ndis.sys     - NDIS_TAG_IM_DEVICE_INSTANCE\r\n",
  "CLb*": " clusbflt.sys - Cluster block storage target driver\r\n",
  "Ucrq": " http.sys     - Request Pool\r\n",
  "NDdb": " ndis.sys     -     DMA block\r\n",
  "NDdc": " ndis.sys     - NDIS_TAG_DCN - Data Center Networking\r\n",
  "NDda": " ndis.sys     - NDIS_TAG_NET_CFG_DACL\r\n",
  "L2T6": " <unknown>    -    ndis\\l2tp / MTAG_TIMERQ\r\n",
  "L2T7": " <unknown>    -    ndis\\l2tp / MTAG_TIMERQITEM\r\n",
  "L2T4": " <unknown>    -    ndis\\l2tp / MTAG_VCTABLE\r\n",
  "L2T5": " <unknown>    -    ndis\\l2tp / MTAG_WORKITEM\r\n",
  "L2T2": " <unknown>    -    ndis\\l2tp / MTAG_TUNNELCB\r\n",
  "L2T3": " <unknown>    -    ndis\\l2tp / MTAG_VCCB\r\n",
  "L2T0": " <unknown>    -    ndis\\l2tp / MTAG_FREED\r\n",
  "L2T1": " <unknown>    -    ndis\\l2tp / MTAG_ADAPTERCB\r\n",
  "NDdt": " ndis.sys     - NDIS_TAG_DFRD_TMR\r\n",
  "NDds": " ndis.sys     - NDIS_TAG_DBG_S\r\n",
  "L2T8": " <unknown>    -    ndis\\l2tp / MTAG_PACKETPOOL\r\n",
  "L2T9": " <unknown>    -    ndis\\l2tp / MTAG_FBUFPOOL\r\n",
  "Qppn": " <unknown>    -      Queued Notifications\r\n",
  "Qppi": " <unknown>    -      Pending Irp structures\r\n",
  "Qpph": " <unknown>    -      PathHash\r\n",
  "Tscf": " netio.sys    - WFP Filter Engine Cached Filter Block\r\n",
  "UlFR": " http.sys     - Dummy Filter Receive Buffer\r\n",
  "AzAp": " HDAudio.sys  - HD Audio Class Driver (Datastore: audio path)\r\n",
  "Qppd": " <unknown>    -      GenPatternDb\r\n",
  "PcSX": " <unknown>    - WDM audio stuff\r\n",
  "Qppa": " <unknown>    -      Pattern blocks\r\n",
  "PnpZ": " nt!pnp       - PNPMGR data model\r\n",
  "Fsrc": " fsrec.sys    - Filesystem recognizer (fsrec.sys)\r\n",
  "Irp+": " nt!vf        - I/O verifier allocated IRP packets\r\n",
  "Qppt": " <unknown>    -      Protocol\r\n",
  "Uc??": " http.sys     - i.e., the case of the leading \"Ul\" or \"Uc\" has been reversed.\r\n",
  "AzAd": " HDAudio.sys  - HD Audio Class Driver (AzPcAudDev)\r\n",
  "L2Tf": " <unknown>    -    ndis\\l2tp / MTAG_PAYLRECD\r\n",
  "L2Tg": " <unknown>    -    ndis\\l2tp / MTAG_PAYLSENT\r\n",
  "L2Td": " <unknown>    -    ndis\\l2tp / MTAG_CTRLRECD\r\n",
  "L2Te": " <unknown>    -    ndis\\l2tp / MTAG_CTRLSENT\r\n",
  "L2Tb": " <unknown>    -    ndis\\l2tp / MTAG_TDIXRDG\r\n",
  "L2Tc": " <unknown>    -    ndis\\l2tp / MTAG_TDIXSDG\r\n",
  "L2Ta": " <unknown>    -    ndis\\l2tp / MTAG_HBUFPOOL\r\n",
  "L2Tn": " <unknown>    -    ndis\\l2tp / MTAG_TDIXROUTE\r\n",
  "L2Tl": " <unknown>    -    ndis\\l2tp / MTAG_L2TPPARAMS\r\n",
  "L2Tm": " <unknown>    -    ndis\\l2tp / MTAG_TUNNELWORK\r\n",
  "L2Tj": " <unknown>    -    ndis\\l2tp / MTAG_ROUTEQUERY\r\n",
  "L2Tk": " <unknown>    -    ndis\\l2tp / MTAG_ROUTESET\r\n",
  "L2Th": " <unknown>    -    ndis\\l2tp / MTAG_INCALL\r\n",
  "L2Ti": " <unknown>    -    ndis\\l2tp / MTAG_UTIL\r\n",
  "PsSb": " nt!ps        - Initial process parameter block (temporary allocation)\r\n",
  "Gump": " win32k.sys                           - GDITAG_UMPD\r\n",
  "Ustm": " win32k!InternalSetTimer              - USERTAG_TIMER\r\n",
  "Ushh": " win32k!HidGetCaps                    - USERTAG_HID\r\n",
  "RaDS": " storport.sys - StorCreateAnsiString storport!_STRING.Buffer\r\n",
  "MmSc": " nt!mm        - subsections used to map data files\r\n",
  "RaDR": " storport.sys - RaidpBuildAdapterBusRelations storport!_DEVICE_RELATIONS\r\n",
  "Afdd": " afd.sys      -     Afd disconnect data buffer\r\n",
  "Afdf": " afd.sys      -     Afd TransmitFile debug data\r\n",
  "Afda": " afd.sys      -     Afd APC buffer (NT 3.51 only)\r\n",
  "AcdM": " <unknown>    - TDI AcdObjectInfoG\r\n",
  "AcdN": " <unknown>    - TDI AcdObjectInfoG\r\n",
  "Afdb": " afd.sys      -     Afd send dgram batch state\r\n",
  "Afdl": " afd.sys      -     Afd lookaside lists buffer\r\n",
  "CCFF": " CCFFilter.sys - Cluster Client Failover Filter\r\n",
  "Afdi": " afd.sys      -     Afd \"set inline mode\" buffer\r\n",
  "Afdh": " afd.sys      -     Afd address list change buffer\r\n",
  "VSAB": " utils.lib - Virtual Machine Storage VSP Utility Library\r\n",
  "Afdt": " afd.sys      -     Afd transport address buffer\r\n",
  "CMVI": " nt!cm        - value index cache tag\r\n",
  "Afdq": " afd.sys      -     Afd routing query buffer\r\n",
  "Afdp": " afd.sys      -     Afd transport IRP buffer\r\n",
  "Ushi": " win32k!AllocateHidDesc               - USERTAG_HIDINPUT\r\n",
  "Afdr": " afd.sys      -     Afd ERESOURCE buffer\r\n",
  "vDMc": " dmvsc.sys - Virtual Machine Dynamic Memory VSC Driver\r\n",
  "Ipfl": " tcpip.sys    - IPsec flow handle\r\n",
  "KSop": " <unknown>    -    object creation parameters\r\n",
  "AfdE": " afd.sys      -     Afd endpoint structure\r\n",
  "AfdD": " afd.sys      -     Afd debug data\r\n",
  "AfdG": " afd.sys      -     Afd group table\r\n",
  "AfdF": " afd.sys      -     Afd TransmitFile info\r\n",
  "AfdA": " afd.sys      -     Afd EA buffer\r\n",
  "AfdC": " afd.sys      -     Afd connection structure\r\n",
  "AfdB": " afd.sys      -     Afd data buffer\r\n",
  "AfdL": " afd.sys      -     Afd local address buffer\r\n",
  "Wmip": " <unknown>    - Wmi General purpose allocation\r\n",
  "AfdI": " afd.sys      -     Afd TDI data\r\n",
  "ARPC": " atmarpc.sys  - ATM ARP Client\r\n",
  "TSNb": " tcpip.sys    - TCP Send NetBuffers\r\n",
  "AfdT": " afd.sys      -     Afd transport info\r\n",
  "AfdW": " afd.sys      -     Afd work item\r\n",
  "AfdQ": " afd.sys      -     Afd work queue item\r\n",
  "AfdP": " afd.sys      -     Afd poll info\r\n",
  "AfdS": " afd.sys      -     Afd security info\r\n",
  "AfdR": " afd.sys      -     Afd remote address buffer\r\n",
  "Ustk": " win32k!HeavyAllocPool                - USERTAG_STACK\r\n",
  "AfdX": " afd.sys      -     Afd context buffer\r\n",
  "PmVE": " partmgr.sys  - Partition Manager volume entry\r\n",
  "smAr": " nt!store or rdyboost.sys - ReadyBoost generic array allocation\r\n",
  "TcRe": " tcpip.sys    - TCP Recovery Buffers\r\n",
  "Urtm": " win32kfull!InitRotationManager       - USERTAG_ROTMGR\r\n",
  "Etwr": " nt!etw       - Etw ReplyQueue entry\r\n",
  "Ushk": " win32k!_RegisterHotKey               - USERTAG_HOTKEY\r\n",
  "Ussb": " win32k!CreateSpb                     - USERTAG_SPB\r\n",
  "WMca": " <unknown>    - WMI MCA Handling\r\n",
  "SeTI": " ksecdd.sys   - Security TargetInfo\r\n",
  "Afd?": " afd.sys      - AFD objects\r\n",
  "Ussd": " win32k!xxxAddShadow                  - USERTAG_SHADOW\r\n",
  "TcRH": " tcpip.sys    - TCP Reassembly Headers\r\n",
  "p2pe": " perm2dll.dll - Permedia2 display driver - permedia.c\r\n",
  "NtfV": " ntfs.sys     -     VPB\r\n",
  "p2pa": " perm2dll.dll - Permedia2 display driver - palette.c\r\n",
  "TcRA": " tcpip.sys    - TCP Reassembly Data\r\n",
  "LSop": " srv.sys      -     SMB1 oplock break wait\r\n",
  "TcRB": " tcpip.sys    - TCP Reassembly Buffers\r\n",
  "TcRD": " tcpip.sys    - TCP Receive DPC Data\r\n",
  "Iptt": " tcpip.sys    - IP Timer Tables\r\n",
  "RaDI": " storport.sys - RaidUnitGetDeviceId\r\n",
  "Ussh": " win32k!zzzSetWindowsHookEx           - USERTAG_HOOK\r\n",
  "Iptc": " tcpip.sys    - IP Transaction Context information\r\n",
  "TcRR": " tcpip.sys    - TCP Receive Requests\r\n",
  "ReAR": " refs.sys     -     Refs Async Cached Read allocation\r\n",
  "HT08": " <unknown>    - GDI Halftone ColorTriadSrcToDev() for RGB-XYZ\r\n",
  "HT09": " <unknown>    - GDI Halftone ColorTriadSrcToDev() for CRTX-FD6XYZ Cache\r\n",
  "Ussj": " win32k!NtUserSendTouchInput          - USERTAG_SENDTOUCHINPUT\r\n",
  "MStx": " refs.sys     - Minstore transaction\r\n",
  "UlCl": " http.sys     - Connection RefTraceLog\r\n",
  "Uswp": " win32k!xxxRegisterUserHungAppHandlers - USERTAG_WOWPROCESSINFO\r\n",
  "HT01": " <unknown>    - GDI Halftone AddCachedDCI() for CurCDCIData\r\n",
  "HT02": " <unknown>    - GDI Halftone GetCachedDCI() for Threshold\r\n",
  "HT03": " <unknown>    - GDI Halftone FindCachedSMP() for CurCSMPData\r\n",
  "HT04": " <unknown>    - GDI Halftone FindCachedSMP() for CurCSMPBmp\r\n",
  "HT05": " <unknown>    - GDI Halftone HT_CreateDeviceHalftoneInfo() for HT_DHI\r\n",
  "HT06": " <unknown>    - GDI Halftone pDCIAdjClr() for DEVCLRADJ\r\n",
  "HT07": " <unknown>    - GDI Halftone ComputeRGB555LUT() for RGBLUT\r\n",
  "LBan": " <unknown>    -     Server announcement\r\n",
  "RaMI": " tcpip.sys    - Raw Socket Message Indication Tags\r\n",
  "RaME": " storport.sys - RiAllocateMiniportDeviceExtension\r\n",
  "CIha": " ci.dll       - Code Integrity hashes\r\n",
  "MStb": " refs.sys     - Minstore table object\r\n",
  "UlCJ": " http.sys     - Config Group Object Pool\r\n",
  "UlCK": " http.sys     - Chunk Tracker\r\n",
  "UlCH": " http.sys     - Config Group Tree Header\r\n",
  "RfFR": " rfcomm.sys   -   RFCOMM frame\r\n",
  "Vi36": " dxgmms2.sys  - Video memory manager pages history\r\n",
  "UlCO": " http.sys     - Connection\r\n",
  "UlCL": " http.sys     - Config Group LogDir\r\n",
  "Vi35": " dxgmms2.sys  - Video memory manager MDL\r\n",
  "UlCC": " http.sys     - Control Channel\r\n",
  "Vi38": " dxgmms2.sys  - Video memory manager allocation fence array\r\n",
  "Vi39": " dxgmms2.sys  - Video memory manager migration table\r\n",
  "Usss": " win32k!xxxBroadcastMessage           - USERTAG_SMS_STRING\r\n",
  "UlCE": " http.sys     - Config Group Tree Entry\r\n",
  "SDk ": " smbdirect.sys - SMB Direct operation\r\n",
  "HcdI": " hcaport.sys - HCAPORT_TAG_HWID\r\n",
  "NtfC": " ntfs.sys     -     CCB\r\n",
  "PooL": " <unknown>    - Phase 0 initialization of the executive component, paged and nonpaged small pool lookaside structures\r\n",
  "IPif": " tcpip.sys    - IP Interfaces\r\n",
  "UlCT": " http.sys     - Config Group Timestamp\r\n",
  "Usst": " win32k!xxxSBTrackInit                - USERTAG_SCROLLTRACK\r\n",
  "Vi14": " dxgmms2.sys  - Video memory manager process commitment info\r\n",
  "NulS": " tlnull.sys   - Null TDI Sockets\r\n",
  "NulR": " tlnull.sys   - Null TDI Requests\r\n",
  "DCvs": " win32kbase!DirectComposition::CVirtualSurfaceMarshaler::_allocate                        - DCOMPOSITIONTAG_VIRTUALSURFACEMARSHALER\r\n",
  "HCID": " bthport.sys  - Bluetooth port driver HCI debug\r\n",
  "RaSL": " tcpip.sys    - Raw Socket Send Message Lists\r\n",
  "RaSM": " tcpip.sys    - Raw Socket Send Messages Requests\r\n",
  "RaSI": " storport.sys - StorUnmapSenseInfo storport!_EXTENDED_REQUEST_BLOCK.Srb.SenseInfoBuffer\r\n",
  "SeSs": " nt!se        - Shared Sids\r\n",
  "NulE": " tlnull.sys   - Null Tl Endpoints\r\n",
  "Vi17": " dxgmms2.sys  - Video memory manager pool\r\n",
  "NulB": " tlnull.sys   - Null TDI Buffers\r\n",
  "HCIT": " bthport.sys  - Bluetooth port driver (HCI)\r\n",
  "HcRs": " hcaport.sys - HCAPORT_TAG_RESOURCE_LIST\r\n",
  "NtfK": " ntfs.sys     -     KEVENT\r\n",
  "wpct": " wof.sys      - Wim chunk table\r\n",
  "Nulr": " tlnull.sys   - Null Tl Requests\r\n",
  "wpcx": " wof.sys      - Wim IO context\r\n",
  "EQSc": " tcpip.sys    - EQoS pacer client\r\n",
  "VoS?": " volsnap.sys  -  VolSnap (Volume Snapshot Driver)\r\n",
  "NtfM": " ntfs.sys     -     NTFS_MCB_ENTRY\r\n",
  "DVSc": " <unknown>    - SrvCall, DAV MiniRedir\r\n",
  "Ala4": " tcpip.sys    -     ALE remote endpoint IPv4 address\r\n",
  "SeHn": " nt!se        - AppContainer Handles\r\n",
  "Ala6": " tcpip.sys    -     ALE remote endpoint IPv6 address\r\n",
  "Uspe": " win32k!AllocPointerInfoNodeList      - USERTAG_POINTERINPUTEVENT\r\n",
  "wpci": " wof.sys      - Wim integrity\r\n",
  "DVSh": " <unknown>    - SharedHeap, DAV MiniRedir\r\n",
  "Dwp9": " <unknown>    - weitekp9 video driver\r\n",
  "Ntf0": " ntfs.sys     -     General pool allocation\r\n",
  "Irpd": " nt!vf        - I/O verifier deferred completion context\r\n",
  "UlUB": " http.sys     - URL Buffer\r\n",
  "UlUC": " http.sys     - Uri Cache Entry\r\n",
  "FCbs": " dxgkrnl!CPoolBufferResourceState::operator new - FLIPCONTENT_BUFFERRESOURCESTATE\r\n",
  "FCbr": " dxgkrnl!CPoolBufferResource::Create - FLIPCONTENT_BUFFERRESOURCE\r\n",
  "NDw2": " ndis.sys     - NDIS_TAG_WMI_OID_SUPPORTED_LIST\r\n",
  "UlUH": " http.sys     - HTTP Unknown Header\r\n",
  "Irpl": " nt!io        - system large IRP lookaside list\r\n",
  "SCCO": " cdrom.sys    -      Set stream buffer\r\n",
  "UlUM": " http.sys     - URL Map\r\n",
  "Ntf?": " ntfs.sys     -     Unkown allocation\r\n",
  "TSq ": " <unknown>    - Terminal Services - Queue - TSQ_TAG\r\n",
  "Irpt": " nt!vf        - I/O verifier per-IRP tracking data\r\n",
  "NDw0": " ndis.sys     - NDIS_TAG_WMI_REG_INFO\r\n",
  "Irps": " nt!io        - system small IRP lookaside list\r\n",
  "MScn": " refs.sys     - Minstore container\r\n",
  "Uswo": " win32k!zzzInitTask                   - USERTAG_WOWTDB\r\n",
  "Usto": " win32k!xxxConnectService             - USERTAG_TOKEN\r\n",
  "LBwi": " <unknown>    -     Work item\r\n",
  "IrpC": " nt!vf        - I/O verifier stack contexts\r\n",
  "IrpB": " nt!vf        - I/O verifier direct I/O double buffer allocation\r\n",
  "RxLv": " rdbss.sys - RDBSS Logical View\r\n",
  "TcpL": " tcpip.sys    - TCP Listeners\r\n",
  "FMis": " fltmgr.sys   -       FLT_INSTANCE structure\r\n",
  "NicT": " mslbfoprovider.sys - Microsoft NDIS LBFO Provider (NIC Teaming)\r\n",
  "VmRi": " volmgrx.sys  - Record information\r\n",
  "FMil": " fltmgr.sys   -       IRP_CTRL completion node stack\r\n",
  "Vi58": " dxgmms2.sys  - Video memory manager release resource command\r\n",
  "FMin": " fltmgr.sys   -       FLT_INSTANCE name\r\n",
  "DmH?": " <unknown>    - DirectMusic hardware synthesizer\r\n",
  "FMic": " fltmgr.sys   -       IRP_CTRL structure\r\n",
  "VmRe": " volmgrx.sys  - Records\r\n",
  "IrpX": " nt!io        - IRP Extension\r\n",
  "SmRw": " mrxsmb10.sys    -      SMB1 read/write path\r\n",
  "TMtq": " dxgkrnl!CTokenQueue::Create                           - TOKENMANAGER_TOKENQUEUE\r\n",
  "Ntfq": " ntfs.sys     -     General Allocation with Quota\r\n",
  "Ntfr": " ntfs.sys     -     ERESOURCE\r\n",
  "Nb14": " netbt.sys    - NetBT lmhosts path\r\n",
  "Ntft": " ntfs.sys     -     SCB (Prerestart)\r\n",
  "Irp ": " <unknown>    - Io, IRP packets\r\n",
  "Ntfv": " ntfs.sys     -     COMPRESSION_SYNC\r\n",
  "Ntfw": " ntfs.sys     -     Workspace\r\n",
  "Ntfx": " ntfs.sys     -     General Allocation\r\n",
  "DCys": " win32kbase!DirectComposition::CYCbCrSurfaceMarshaler::_allocate                          - DCOMPOSITIONTAG_YCBCRSURFACEMARSHALER\r\n",
  "Ustx": " win32k!NtUserDrawCaptionTemp         - USERTAG_TEXT\r\n",
  "Usty": " win32k!NtUserResolveDesktopForWOW    - USERTAG_TEXT2\r\n",
  "AlSP": " tcpip.sys    -     ALE secure socket policy\r\n",
  "Plcl": " <unknown>    - Cache aware pushlock entry. One per processor\r\n",
  "Ustd": " win32k!TrackAddDesktop               - USERTAG_TRACKDESKTOP\r\n",
  "Ntfc": " ntfs.sys     -     CCB_DATA\r\n",
  "Ntfd": " ntfs.sys     -     DEALLOCATED_CLUSTERS\r\n",
  "@SB ": " <unknown>    - (Intel video driver) Soft BIOS\r\n",
  "Ntff": " ntfs.sys     -     FCB_DATA\r\n",
  "RSLT": " <unknown>    -      Long term data\r\n",
  "MiCf": " nt!mm        - Mm compressed Control Flow Guard valid target RVA list\r\n",
  "Ustn": " win32k!AllocateW32Thread             - USERTAG_THREADINFONP\r\n",
  "Hvlm": " nt!Hvl       - Temporary MDL for the Hvl component.\r\n",
  "Ntfl": " ntfs.sys     -     LCB\r\n",
  "Ntfm": " ntfs.sys     -     NTFS_MCB_ARRAY\r\n",
  "Ntfn": " ntfs.sys     -     SCB_NONPAGED\r\n",
  "Ntfo": " ntfs.sys     -     SCB_INDEX normalized named buffer\r\n",
  "NtfQ": " ntfs.sys     -     QUOTA_CONTROL_BLOCK\r\n",
  "NtfR": " ntfs.sys     -     READ_AHEAD_THREAD\r\n",
  "NtfS": " ntfs.sys     -     SCB_INDEX\r\n",
  "NtfT": " ntfs.sys     -     SCB_SNAPSHOT\r\n",
  "PfRQ": " nt!pf        - Pf Prefetch request buffers\r\n",
  "HvlP": " nt!Hvl       - Hypercall marshalling pages for the Hvl component.\r\n",
  "Plcp": " <unknown>    - Cache aware pushlock list (array of puchlock addresses)\r\n",
  "ReSe": " <unknown>    - Resource Semaphore\r\n",
  "UlAP": " http.sys     - App Pool Process\r\n",
  "CKRT": " <multiple>   - Cluster Kernel RTL library\r\n",
  "AlSs": " tcpip.sys    -     ALE socket security context\r\n",
  "CMVw": " nt!cm        - registry mapped view of file\r\n",
  "TcAR": " tcpip.sys    - TCP Abort Requests\r\n",
  "SeHa": " nt!se        - Security Handle Array\r\n",
  "HPmi": " hcaport.sys - HCAPORT_TAG_PMI_EXTENSION\r\n",
  "AlSm": " tcpip.sys    -     ALE Secondary App Meta Data\r\n",
  "NtfD": " ntfs.sys     -     DEALLOCATED_RECORDS\r\n",
  "NtfE": " ntfs.sys     -     INDEX_CONTEXT\r\n",
  "NtfF": " ntfs.sys     -     FCB_INDEX\r\n",
  "PfRL": " nt!pf        - Pf Prefetch read list\r\n",
  "NtfI": " ntfs.sys     -     IO_CONTEXT\r\n",
  "AlSe": " nt!alpc      - ALPC client security\r\n",
  "AlSc": " nt!alpc      - ALPC section\r\n",
  "NtfN": " ntfs.sys     -     NUKEM\r\n",
  "DEog": " devolume.sys - Drive extender old GUID array\r\n",
  "MouC": " mouclass.sys - Mouse Class Driver\r\n",
  "FLex": " <unknown>    - exclusive file lock\r\n",
  "NDw1": " ndis.sys     - NDIS_TAG_WMI_GUID_TO_OID\r\n",
  "Ituo": " tcpip.sys    - IPsec outbound tunnel session security context\r\n",
  "Itui": " tcpip.sys    - IPsec inbound packet tunnel security context\r\n",
  "Nb19": " netbt.sys    - NetBT lmhosts data\r\n",
  "Nb18": " netbt.sys    - NetBT lmhosts file\r\n",
  "Nb17": " netbt.sys    - NetBT registry path\r\n",
  "Nb16": " netbt.sys    - NetBT timer entry\r\n",
  "MouH": " mouhid.sys   - Mouse HID mapper Driver\r\n",
  "Nb13": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb12": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb11": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb10": " netbt.sys    - NetBT domain address list\r\n",
  "SmAd": " mrxsmb10.sys    -      SMB1 session setup/admin exchange\r\n",
  "FtU ": " <unknown>    - Fault tolerance driver\r\n",
  "WlGc": " writelog.sys - Writelog global context\r\n",
  "Gdrs": " win32k.sys                           - GDITAG_DRVSUP\r\n",
  "DCch": " win32kbase!DirectComposition::CChannelHandleTable::_allocate                             - DCOMPOSITIONTAG_CHANNELHANDLETABLE\r\n",
  "ScC9": " classpnp.sys -  Device Control SRB\r\n",
  "SeTd": " nt!se        - Security Token dynamic part\r\n",
  "FIcs": " fileinfo.sys - FileInfo FS-filter Stream Context\r\n",
  "FIcp": " fileinfo.sys - FileInfo FS-filter Extra Create Parameter\r\n",
  "FIcv": " fileinfo.sys - FileInfo FS-filter Volume Context\r\n",
  "SeTa": " nt!se        - Security Temporary Array\r\n",
  "SrDL": " sr.sys       -         Device list\r\n",
  "SeTl": " nt!se        - Security Token Lock\r\n",
  "SrDB": " sr.sys       -         Debug information for lookup blob\r\n",
  "Lrwq": " <unknown>    -     Work queue item\r\n",
  "FCpc": " dxgkrnl!CFlipPresentCancel::operator new - FLIPCONTENT_PRESENTCANCEL\r\n",
  "FCpb": " dxgkrnl!CreateFlipPropertySet - FLIPCONTENT_PROPERTYBLOBBUFFER\r\n",
  "rbTo": " <unknown>    - RedBook - Cached table of contents\r\n",
  "PXj": " ndproxy.sys - PX_TRANSLATE_CALL_TAG\r\n",
  "Ifws": " tcpip.sys    - IPsec forward state\r\n",
  "FCpu": " dxgkrnl!CFlipManager::ProcessTokenCreate - FLIPCONTENT_PRESENTUPDATE\r\n",
  "Lrwb": " <unknown>    -     Write behind buffer header\r\n",
  "FIcn": " fileinfo.sys - FileInfo FS-filter Create Retry Path\r\n",
  "FCps": " dxgkrnl!CFlipPropertySet::operator new - FLIPCONTENT_PROPERTYSET\r\n",
  "DCya": " win32kbase!DirectComposition::CSharedCompositionAmbientLightMarshaler::_allocate         - DCOMPOSITIONTAG_SHAREDCOMPOSITIONAMBIENTLIGHTMARSHALER\r\n",
  "NDwr": " ndis.sys     - NDIS_TAG_WMI_REQUEST\r\n",
  "EQOw": " tcpip.sys    - EQoS policy owner\r\n",
  "NLcc": " tcpip.sys    - Network Layer Client Contexts\r\n",
  "NDwx": " ndis.sys     - NDIS_TAG_WOL_XLATE\r\n",
  "Txdr": " ntfs.sys     - TXF_DEFAULT_READER_SECTION\r\n",
  "SrRR": " sr.sys       -         Registry information\r\n",
  "Txdl": " ntfs.sys     - TXF_DELETED_LINK\r\n",
  "Nptx": " <unknown>    - NPT Packets\r\n",
  "SrRH": " sr.sys       -         Reparse data size\r\n",
  "Nptr": " <unknown>    - NPT Receive Completes\r\n",
  "Npts": " <unknown>    - NPT Send sCompletes\r\n",
  "NDwi": " ndis.sys     - NDIS_TAG_WORK_ITEM\r\n",
  "NDwh": " ndis.sys     - NDIS_TAG_WRAPPER_HANDLE\r\n",
  "PmIB": " partmgr.sys  - Partition Manager buffer for IOCTL processing\r\n",
  "AzRr": " HDAudio.sys  - HD Audio Class Driver (RedirectedRender)\r\n",
  "SrRB": " sr.sys       -         Rename buffer\r\n",
  "PoEl": " raspppoe.sys - MTAG_FREED\r\n",
  "PoEm": " raspppoe.sys - MTAG_LLIST_WORKITEMS\r\n",
  "DCkt": " win32kbase!DirectComposition::CSkewTransformMarshaler::_allocate                         - DCOMPOSITIONTAG_SKEWTRANSFORMMARSHALER\r\n",
  "PoEh": " raspppoe.sys - MTAG_CALL\r\n",
  "PoEi": " raspppoe.sys - MTAG_HANDLETABLE\r\n",
  "PoEj": " raspppoe.sys - MTAG_HANDLECB\r\n",
  "PoEk": " raspppoe.sys - MTAG_TIMERQ\r\n",
  "PoEd": " raspppoe.sys - MTAG_PACKETPOOL\r\n",
  "PoEe": " raspppoe.sys - MTAG_PPPOEPACKET\r\n",
  "PoEf": " raspppoe.sys - MTAG_TAPIPROV\r\n",
  "PoEg": " raspppoe.sys - MTAG_LINE\r\n",
  "SmRb": " mrxsmb10.sys    -      SMB1 remote boot\r\n",
  "PoEa": " raspppoe.sys - MTAG_ADAPTER\r\n",
  "PoEb": " raspppoe.sys - MTAG_BINDING\r\n",
  "PoEc": " raspppoe.sys - MTAG_BUFFERPOOL\r\n",
  "DCkf": " win32kbase!DirectComposition::CKeyframeAnimationMarshaler::_allocate                     - DCOMPOSITIONTAG_KEYFRAMEANIMATIONMARSHALER\r\n",
  "xSMB": " smbmrx.sys - IFSKIT sample SMB mini-redirector\r\n",
  "Uisc": " win32k!DWMSetInputSystemOutputConfig - USERTAG_INPUT_CONFIG\r\n",
  "smTi": " rdyboost.sys -         ReadyBoost debug IO trace buffer\r\n",
  "Usft": " win32k!CreateValidTouchInputInfo     - USERTAG_FORWARDTOUCHMESSAGE\r\n",
  "Tspk": " ksecdd.sys   - TS Package kernel mode client allocations\r\n",
  "PoEu": " raspppoe.sys - MTAG_UTIL\r\n",
  "AzRR": " HDAudio.sys  - HD Audio Class Driver (SpdifEmbeddedRender, SpdifOut, Headphone, HBDAout)\r\n",
  "DCg3": " win32kbase!DirectComposition::CTransform3DGroupMarshaler::_allocate                      - DCOMPOSITIONTAG_TRANSFORM3DGROUPMARSHALER\r\n",
  "LSnd": " <unknown>    - WDM mini sound driver for Logitech video camera\r\n",
  "NvLH": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLD": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLE": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "ObSt": " nt!ob        - Object Manager temporary storage\r\n",
  "LSnn": " srv2.sys     -     SMB2 netname\r\n",
  "LSni": " srv.sys      -     SMB1 BlockTypeNameInfo\r\n",
  "LSnh": " srv.sys      -     SMB1 nonpaged block header\r\n",
  "Ipwi": " tcpip.sys    - IPsec work item\r\n",
  "DPrf": " <unknown>    - Disk performance filter driver\r\n",
  "Ikmb": " tcpip.sys    - IPsec key module blob\r\n",
  "NDkr": " ndis.sys     - NDIS_TAG_NDK - Kernel Mode Network Direct (kRDMA)\r\n",
  "NvLT": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "UdMI": " tcpip.sys    - UDP Message Indications\r\n",
  "NvLP": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "ObSc": " nt!ob        - Object security descriptor cache block\r\n",
  "NvLR": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLS": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLm": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "Tslc": " tcpip.sys    - WFP TL Shim Layer Cache\r\n",
  "NvLd": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLa": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLc": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "CLB*": " clusbflt.sys - Cluster block storage target driver\r\n",
  "Ggb ": " win32k!RFONTOBJ::pgbCheckGlyphCache  - GDITAG_GLYPHBLOCK\r\n",
  "Covr": " nt!cov       - Code Coverage pool tag\r\n",
  "SAad": " srvnet.sys   - SrvAdmin buffer\r\n",
  "NDfn": " ndis.sys     - NDIS_TAG_FILE_NAME\r\n",
  "NvLr": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "NvLs": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "xCVD": " mrxdav.sys - AsyncEngineContext Tag\r\n",
  "Adap": " <unknown>    - Adapter objects\r\n",
  "SC??": " <unknown>    - Smart card driver tags\r\n",
  "TcCR": " tcpip.sys    - TCP Connect Requests\r\n",
  "Usti": " win32k!AllocateW32Thread             - USERTAG_THREADINFO\r\n",
  "Lrea": " <unknown>    -     EA related allocations\r\n",
  "TcCM": " tcpip.sys    - TCP Congestion Control Manager Contexts\r\n",
  "SPMp": " nt!po        - Kernel Scenario Power Manager Policies.\r\n",
  "Lref": " <unknown>    -     Reference history (debug only)\r\n",
  "Udpi": " win32k!CreateSystemFontsForDpi       - USERTAG_DPIMETRICS\r\n",
  "TcCC": " tcpip.sys    - TCP Create And Connect Tcb Pool\r\n",
  "NDel": " ndis.sys     - NDIS debugging event log\r\n",
  "RxIr": " rdbss.sys - RDBSS RxContext\r\n",
  "SeTn": " nt!se        - Security Captured Type Name information\r\n",
  "Gbdl": " win32k!BRUSH::bAddIcmDIB             - GDITAG_ICM_DIB_LIST\r\n",
  "Vtfd": " win32k.sys                           - GDITAG_VF_FONT\r\n",
  "TcCo": " tcpip.sys    - TCP Compartment\r\n",
  "Wrph": " <unknown>    - WAN_HEADER_TAG\r\n",
  "Ggbl": " <unknown>    -     Gdi look aside buffers\r\n",
  "Gsux": " win32k.sys                           - GDITAG_SFM\r\n",
  "SeSi": " nt!se        - Security SID\r\n",
  "UsMP": " win32k!GeneratePointerMessageFromMouse - USERTAG_MOUSEINPOINTER\r\n",
  "MSkb": " refs.sys     - Minstore keys buffer\r\n",
  "HcUc": " hcaport.sys - HCAPORT_TAG_UCONTEXT\r\n",
  "RaRL": " storport.sys - RaidInitializeResourceList storport!_RAID_RESOURCE_LIST\r\n",
  "UlFT": " http.sys     - Filter Channel\r\n",
  "RaRS": " storport.sys - RaidUnitAllocateResources\r\n",
  "MSkr": " refs.sys     - Minstore CmsKeyRules object\r\n",
  "UlFW": " http.sys     - Filter Write Tracker\r\n",
  "UsIc": " win32k!NSInstrumentation::CSortedVector::Create   - USERTAG_SORTED_VECTOR\r\n",
  "UsIb": " win32k!NSInstrumentation::CReferenceTracker::CReferenceCountedType::BeginTrack   - USERTAG_REFERENCE_COUNTED_OBJECT_HANDLE\r\n",
  "Nnbl": " netio.sys    - NetIO NetBufferLists\r\n",
  "ScCe": " cdrom.sys    -      Request sync event\r\n",
  "VSVL": " VMBusVideoM.sys - Virtual Machine Synthetic Video Display Driver\r\n",
  "Nnbf": " netio.sys    - NetIO NetBuffers\r\n",
  "MmSt": " nt!mm        - Mm section object prototype ptes\r\n",
  "RaRl": " storport.sys - RaidBusEnumeratorAllocateReportLunsResources storport!_BUS_ENUM_RESOURCES.DataBuffer\r\n",
  "Wrpf": " <unknown>    - FREE_TAG (checked builds only)\r\n",
  "RmPt": " netio.sys    - Rtl Mapping Page Table Entries\r\n",
  "SDf ": " smbdirect.sys - SMB Direct LAM objects\r\n",
  "MSPi": " refs.sys     - Minstore generic/untagged allocation\r\n",
  "Pccr": " pacer.sys    - PACER Filter Clone Requests\r\n",
  "Usci": " win32k!InitSystemThread              - USERTAG_CLIENTTHREADINFO\r\n",
  "rbSc": " <unknown>    - RedBook - Stream completion context\r\n",
  "Npta": " <unknown>    - NPT Addresses\r\n",
  "BvHI": " netiobvt.sys - BVT HT Items\r\n",
  "FSfm": " nt!fsrtl     - File System Run Time Fast Mutex Lookaside List\r\n",
  "HT13": " <unknown>    - GDI Halftone ComputeHTCellRegress() for pThresholds\r\n",
  "HT12": " <unknown>    - GDI Halftone ThresholdsFromYData() for pYData\r\n",
  "HT11": " <unknown>    - GDI Halftone CreateDyesColorMappingTable() for DyeMappingTable\r\n",
  "HT10": " <unknown>    - GDI Halftone CreateDyesColorMappingTable() for DevPrims\r\n",
  "NbL4": " netbt.sys    - NetBT lower connection\r\n",
  "Gnff": " win32k.sys                           - GDITAG_NETWORKED_FONT_FILE_TABLE\r\n",
  "HT15": " <unknown>    - GDI Halftone CalculateStretch() for PrimColorInfo\r\n",
  "Ipis": " tcpip.sys    - IPsec inbound sequence info\r\n",
  "VoSa": " volsnap.sys  -      Application information allocations\r\n",
  "BvHT": " netiobvt.sys - BVT HT Tables\r\n",
  "RxNr": " rdbss.sys - RDBSS NetRoot\r\n",
  "VHde": " vmusbhub.sys - Virtual Machine USB Hub Driver (descriptor)\r\n",
  "Sdp?": " <unknown>    - Bluetooth SDP functionality in BTHPORT.sys\r\n",
  "AleN": " tcpip.sys    -     ALE notify context\r\n",
  "UcCO": " http.sys     - Client Connection\r\n",
  "HcCq": " hcaport.sys - HCAPORT_TAG_CQUEUE\r\n",
  "Vi29": " dxgmms2.sys  - Video memory manager DMA pool\r\n",
  "Vi28": " dxgmms2.sys  - Video memory manager mutex\r\n",
  "rbSx": " <unknown>    - RedBook - Stream Xtra info\r\n",
  "PXf": " ndproxy.sys - PX_LINECALLINFO_TAG\r\n",
  "Vi24": " dxgmms2.sys  - Video memory manager DMA buffer allocation list\r\n",
  "Vi27": " dxgmms2.sys  - Video memory manager resource list\r\n",
  "Vi26": " dxgmms2.sys  - Video memory manager protected allocation\r\n",
  "Vi21": " dxgmms2.sys  - Video memory manager segment descriptor\r\n",
  "Vi20": " dxgmms2.sys  - Video memory manager commitment info\r\n",
  "Vi23": " dxgmms2.sys  - Video memory manager DMA buffer allocation table\r\n",
  "UlFD": " http.sys     - Noncached File Data\r\n",
  "RPrt": " rstorprt.sys - Remote Storage Port Driver\r\n",
  "UsI2": " win32k!NSInstrumentation::CBackTraceBucket::CreateContext   - USERTAG_BACKTRACE_BUCKET_CONTEXT\r\n",
  "UsI1": " win32k!NSInstrumentation::CBackTraceBucket::Create   - USERTAG_BACKTRACE_BUCKET\r\n",
  "SDj ": " smbdirect.sys - SMB Direct SQ work requests\r\n",
  "UsI7": " win32k!NSInstrumentation::CPrioritizedWriterLock::Create   - USERTAG_PRIORITIZED_WRITER_LOCK\r\n",
  "UsI6": " win32k!NSInstrumentation::CLeakTrackingAllocator::Create   - USERTAG_LEAK_TRACKING_ALLOCATOR\r\n",
  "UsI5": " win32k!NSInstrumentation::CPlatformSignal::Create   - USERTAG_INSTRUMENTATION_EVENT\r\n",
  "UsI4": " win32k!NSInstrumentation::CBloomFilter::Create   - USERTAG_BLOOMFILTER\r\n",
  "UsI9": " win32k!NSInstrumentation::CReferenceTracker::Create   - USERTAG_REFERENCE_TRACKER\r\n",
  "UsI8": " win32k!NSInstrumentation::CPointerHashTable::Create   - USERTAG_POINTER_HASH_TABLE\r\n",
  "Stdq": " netio.sys    - WFP stream DPC queue\r\n",
  "HcCm": " hcaport.sys - HCAPORT_TAG_CM\r\n",
  "Usus": " win32k!MsgSQMGetMsgList              - USERTAG_UIPI_SQM\r\n",
  "ScCu": " cdrom.sys    -      Read buffer for dvd key\r\n",
  "CMCa": " nt!cm        - Configuration Manager Cache (registry)\r\n",
  "ReTo": " refs.sys     -     DEVICE_MANAGE_DATA_SET_ATTRIBUTES RefsFileOffloadLookasideList\r\n",
  "SeSd": " nt!se        - Security Descriptor\r\n",
  "ATmp": " AppTag mount point\r\n",
  "Usub": " win32k!NtUserToUnicodeEx             - USERTAG_UNICODEBUFFER\r\n",
  "Usua": " win32k!TabletButtonHandler           - USERTAG_TABLETBUTTONUSAGE\r\n",
  "KAPC": " nt!io              - I/O SubSystem HardError APC\r\n",
  "DCxc": " win32kbase!DirectComposition::CCrossChannelChildVisualMarshaler::_allocate               - DCOMPOSITIONTAG_CROSSCHANNELCHILDVISUALMARSHALER\r\n",
  "Prof": " <unknown>    - Profile objects\r\n",
  "UsKf": " win32k!InitCreateUserCrit            - USERTAG_FASTMUTEX\r\n",
  "Proc": " nt!ps        - Process objects\r\n",
  "SrRG": " sr.sys       -         Logger context\r\n",
  "Ppen": " nt!pnp       - routines to perform device enumeration\r\n",
  "Vi30": " dxgmms2.sys  - Video memory manager slot table\r\n",
  "Gqnk": " win32k!bComputeQuickLookup           - GDITAG_LFONT_QUICKLOOKUP\r\n",
  "AlRr": " nt!Alpc      - ALPC resource reserves\r\n",
  "SV??": " <unknown>       - Synthetic Video Driver\r\n",
  "DCds": " win32kbase!DirectComposition::CDropShadowMarshaler::_allocate                            - DCOMPOSITIONTAG_DROPSHADOWMARSHALER\r\n",
  "Uscm": " win32k!InitScancodeMap               - USERTAG_SCANCODEMAP\r\n",
  "V2ic": " vhdmp.sys    - VHD2 external I/O allocation\r\n",
  "SeIf": " nt!se        - Security Image Filename\r\n",
  "PfSA": " nt!pf        - Pf Prefetch support array\r\n",
  "DpDc": " FsDepends.sys - FsDepends Dependency Context Block\r\n",
  "DpDl": " FsDepends.sys - FsDepends Dependency List Block\r\n",
  "Msdv": " <unknown>    - WDM mini driver for IEEE 1394 DV Camera and VCR\r\n",
  "Fcbl": " <unknown>    - EXIFS FCBlock\r\n",
  "AlRe": " nt!alpc      - ALPC section region\r\n",
  "UlRT": " http.sys     - RefTraceLog PoolTag\r\n",
  "ParL": " <unknown>    - Parallel link driver\r\n",
  "wppm": " wof.sys      - Wim IO parameters\r\n",
  "SeSp": " nt!se        - Scoped Policy\r\n",
  "Wan?": " <unknown>    - NdisWan Tags (PPP Framing module for Remote Access)\r\n",
  "MSur": " refs.sys     - Minstore undo record\r\n",
  "VusW": " vmusbstub.sys - Virtual Machine USB Stub Driver (WDF)\r\n",
  "DCpe": " win32kbase!DirectComposition::CSharedReadPrimitiveColorMarshaler::_allocate              - DCOMPOSITIONTAG_SHAREDREADPRIMITIVECOLORMARSHALER\r\n",
  "PSlo": " win32k.sys                           - GDITAG_PANNING_SHADOWLOCK\r\n",
  "Txcl": " ntfs.sys     - TXF_CLR_RESERVATION_CHUNK\r\n",
  "MQAH": " mqac.sys     - MSMQ driver, Heap allocations\r\n",
  "Ghml": " win32k.sys                           - GDITAG_HMGR_LOCK\r\n",
  "I4ai": " tcpip.sys    - IPv4 Local Address Identifiers\r\n",
  "MQAG": " mqac.sys     - MSMQ driver, CGroup allocations\r\n",
  "SeSv": " nt!se        - Security SID values block\r\n",
  "MQAA": " mqac.sys     - MSMQ driver, AVL allocations\r\n",
  "Ghmg": " <unknown>    -     Gdi handle manager objects\r\n",
  "MQAC": " mqac.sys     - MSMQ driver, generic allocations\r\n",
  "MQAB": " mqac.sys     - MSMQ driver, CCursor allocations\r\n",
  "UlSD": " http.sys     - Security Data\r\n",
  "Wfpn": " netio.sys    - WFP NBL info container\r\n",
  "I6ua": " tcpip.sys    - IPv6 Local Unicast Addresses\r\n",
  "CcOb": " nt!cc        - Cache Manager Overlap Bcb\r\n",
  "Ic6h": " tcpip.sys    - ICMP IPv6 Headers\r\n",
  "MQAT": " mqac.sys     - MSMQ driver, CTransaction allocations\r\n",
  "UlBO": " http.sys     - Outstanding i/o\r\n",
  "UsKv": " win32k!ReadTabletButtonConfig        - USERTAG_KEYVALUEINFORMATION\r\n",
  "MQAQ": " mqac.sys     - MSMQ driver, CQueue allocations\r\n",
  "Ic6c": " tcpip.sys    - ICMP IPv6 Control data\r\n",
  "DCfp": " win32kbase!DirectComposition::CProxyGeometryClipMarshaler::_allocate                     - DCOMPOSITIONTAG_PROXYGEOMETRYCLIPMARSHALER\r\n",
  "Ip??": " ipsec.sys    - IP Security (IPsec)\r\n",
  "WanS": " <unknown>    - AfCB/SapCB/VcCB\r\n",
  "RxCt": " mrxsmb.sys - RXCE transport\r\n",
  "DCdp": " win32kbase!DirectComposition::COverlayRenderTargetMarshaler::_allocate                   - DCOMPOSITIONTAG_OVERLAYRENDERTARGETMARSHALER\r\n",
  "Gvds": " win32k!MulEnablePDEV                 - GDITAG_HDEV\r\n",
  "NDtk": " ndis.sys     - NDIS_TAG_NBL_TRACKER - Lost packet diagnostics\r\n",
  "DCcy": " win32kbase!DirectComposition::CCursorVisualMarshaler::_allocate                          - DCOMPOSITIONTAG_CURSORVISUALMARSHALER\r\n",
  "Gla@": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_BRUSH_TYPE\r\n",
  "Lxpt": " <unknown>    -     Transport\r\n",
  "PfAS": " nt!pf        - Pf Prefetch support array\r\n",
  "SeSa": " nt!se        - Security SID and Attributes\r\n",
  "DCjs": " win32kbase!DirectComposition::CSurfaceBrushMarshaler::_allocate                          - DCOMPOSITIONTAG_SURFACEBRUSHMARSHALER\r\n",
  "Usgi": " win32k!NtUserSendGestureInput        - USERTAG_GESTUREINFO\r\n",
  "Usgh": " win32k!NtUserUserHandleGrantAccess   - USERTAG_GRANTEDHANDLES\r\n",
  "DCjw": " win32kbase!DirectComposition::CWindowBackdropBrushMarshaler::_allocate                   - DCOMPOSITIONTAG_WINDOWBACKDROPBRUSHMARSHALER\r\n",
  "Usgd": " win32k!SetGestureConfigSettings      - USERTAG_GESTUREDATA\r\n",
  "wpRD": " wof.sys      - Wim large read buffer\r\n",
  "SmSe": " mrxsmb10.sys    -      SMB1   Session  (special build only)\r\n",
  "Gpid": " win32k!NtGdiSetPUMPDOBJ              - GDITAG_PRINTCLIENTID\r\n",
  "Usgc": " win32k!_StoreGestureConfig           - USERTAG_GESTURECONFIG\r\n",
  "Gdcf": " win32k.sys                           - GDITAG_DC_FREELIST\r\n",
  "SeSb": " nt!se        - Security Secure Boot\r\n",
  "DCje": " win32kbase!DirectComposition::CEffectBrushMarshaler::_allocate                           - DCOMPOSITIONTAG_EFFECTBRUSHMARSHALER\r\n",
  "UlRP": " http.sys     - Request Buffer\r\n",
  "Usgt": " win32k!AddGhost                      - USERTAG_GHOST\r\n",
  "Ulfc": " http.sys     - Uri Filter Context\r\n",
  "SmSr": " mrxsmb10.sys    -      SMB1   Server  (special build only)\r\n",
  "DCjm": " win32kbase!DirectComposition::CMaskBrushMarshaler::_allocate                             - DCOMPOSITIONTAG_MASKBRUSHMARSHALER\r\n",
  "ScL?": " classpnp.sys -   Classpnp\r\n",
  "ScCV": " cdrom.sys    -      Read buffer for dvd/rpc2 check\r\n",
  "MmTp": " nt!mm        - Store eviction thread params\r\n",
  "DpVc": " FsDepends.sys - FsDepends Volume Context Block\r\n",
  "Nb28": " netbt.sys    - NetBT name server addresses\r\n",
  "Nb29": " netbt.sys    - NetBT registry string\r\n",
  "DCdn": " win32kbase!DirectComposition::CSharedReadRemotingRenderTargetMarshaler::_allocate        - DCOMPOSITIONTAG_SHAREDREADREMOTINGRENDERTARGETMARSHALER\r\n",
  "smKG": " nt!store     -         ReadyBoost encryption key registry path buffer\r\n",
  "UlTD": " http.sys     - UL_TRANSPORT_ADDRESS\r\n",
  "Nb22": " netbt.sys    - NetBT work item context\r\n",
  "Nb23": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb20": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb21": " netbt.sys    - NetBT control object\r\n",
  "Nb26": " netbt.sys    - NetBT device exports\r\n",
  "Nb27": " netbt.sys    - NetBT bind list cache\r\n",
  "Wdm ": " <unknown>    - WDM\r\n",
  "Nb25": " netbt.sys    - NetBT device bindings\r\n",
  "Mmpv": " nt!mm        - Physical view VAD info\r\n",
  "Gfsm": " win32k!GreCreateFastMutex            - GDITAG_FAST_MUTEX\r\n",
  "Gfsb": " win32k.sys                           - GDITAG_FONT_SUB\r\n",
  "MsvC": " ksecdd.sys   - Msv/Ntlm client package\r\n",
  "CPnp": " classpnp.sys - ClassPnP transfer packets\r\n",
  "MSav": " refs.sys     - Minstore AVL table\r\n",
  "Usct": " win32k!CkptRestore                   - USERTAG_CHECKPT\r\n",
  "Gla:": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_LFONT_TYPE\r\n",
  "Gla;": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_RFONT_TYPE\r\n",
  "Gla8": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_PAL_TYPE\r\n",
  "Uscw": " win32k!CacheAxisChildIndex           - USERTAG_CONTACTRELATIVE\r\n",
  "SslC": " ksecdd.sys   - SSL kernel mode client allocations\r\n",
  "Mmpr": " nt!mm        - Mm physical VAD roots\r\n",
  "LSSL": " srv2.sys     -     SMBLIB allocation\r\n",
  "Gla1": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_DC_TYPE\r\n",
  "Gla4": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_RGN_TYPE\r\n",
  "Gla5": " win32k.sys                           - GDITAG_HMGR_LOOKASIDE_SURF_TYPE\r\n",
  "WSNP": " WFPSamplerCalloutDriver.sys - WFPSampler Callout Driver NDIS Pool\r\n",
  "LBtn": " <unknown>    -     Transport name\r\n",
  "WlMp": " writelog.sys - Writelog marker payload\r\n",
  "Im* ": " <unknown>    - Imapi.sys from adaptec\r\n",
  "DCma": " win32kbase!DirectComposition::CManipulationTransformMarshaler::_allocate                 - DCOMPOSITIONTAG_MANIPULATIONTRANSFORMMARSHALER\r\n",
  "DCdl": " win32kbase!DirectComposition::CCompositionDistantLight::_allocate                        - DCOMPOSITIONTAG_DISTANTLIGHTMARSHALER\r\n",
  "Gpgb": " win32k!EngPlgBlt                     - GDITAG_PLGBLT_DATA\r\n",
  "TcBW": " tcpip.sys    - TCP Bandwidth Allocations\r\n",
  "RSIO": " <unknown>    -      Ioctl Queue\r\n",
  "svxC": " svhdxflt.sys -         Create File processing\r\n",
  "PcNw": " <unknown>    - WDM audio stuff\r\n",
  "LB??": " <unknown>    - LM Datagram receiver allocations\r\n",
  "MmDT": " nt!mm        - Mm debug\r\n",
  "DCdk": " win32kbase!DirectComposition::CDcompTargetGroupMarshaler::_allocate                      - DCOMPOSITIONTAG_DCOMPTARGETGROUPMARSHALER\r\n",
  "KCfe": " <unknown>    - Kernel COM factory entry\r\n",
  "Dprt": " dxgkrnl.sys  - Video port for Vista display drivers\r\n",
  "MmDm": " nt!mm        - deferred MmUnlock entries\r\n",
  "MmDb": " nt!mm        - NtMapViewOfSection service\r\n",
  "Gtff": " win32k.sys                           - GDITAG_TRUSTED_FONT_FILE_TABLE\r\n",
  "Uscb": " win32k!_ConvertMemHandle             - USERTAG_CLIPBOARD\r\n",
  "MmDp": " nt!mm        - Lost delayed write context\r\n",
  "TcpB": " tcpip.sys    - TCP Offload Blocks\r\n",
  "TcpA": " tcpip.sys    - TCP DMA buffers\r\n",
  "Lrte": " <unknown>    -     Transport event.\r\n",
  "TSlc": " rdpwd.sys    - RDPWD - Hydra Licensing\r\n",
  "Lrtc": " <unknown>    -     Transport connection\r\n",
  "TcpE": " tcpip.sys    - TCP Endpoints\r\n",
  "Gh00": " win32k.sys                           - GDITAG_HMGR_START\r\n",
  "Nrtr": " netio.sys    - NRT record\r\n",
  "R300": " <unknown>    - ATI video driver\r\n",
  "TcpI": " tcpip.sys    - TCP ISN buffers\r\n",
  "TcpO": " tcpip.sys    - TCP Offload Requests\r\n",
  "TcpN": " tcpip.sys    - TCP Name Service Interfaces\r\n",
  "TcpM": " tcpip.sys    - TCP Offload Miscellaneous buffers\r\n",
  "NvLA": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "WlFc": " writelog.sys - Writelog fsd context\r\n",
  "GFdk": " win32k.sys                           - GDITAG_UMFD_KERNEL_ALLOCATION\r\n",
  "USBD": " <unknown>    - Universal Serial Bus Class Driver\r\n",
  "TcpP": " tcpip.sys    - TCP Processor Arrays\r\n",
  "USBB": " bthusb.sys   - Bluetooth USB minidriver\r\n",
  "NvLC": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "VsCN": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney neighbor context)\r\n",
  "ScIO": " classpnp.sys - ClassPnP device control\r\n",
  "WKSM": " werkernel.sys - WER kernel mode reporting allocation of WERSVC message\r\n",
  "Muta": " <unknown>    - Mutant objects\r\n",
  "VsCH": " vmswitch.sys - Virtual Machine Network Switch Driver (chimney handle)\r\n",
  "Gicm": " win32k.sys                           - GDITAG_ICM\r\n",
  "SeUs": " nt!se        - Security Captured Unicode string\r\n",
  "svxr": " svhdxflt.sys -         File read operations\r\n",
  "ATIX": " <unknown>    - WDM mini drivers for ATI tuner, xbar, etc.\r\n",
  "DCdh": " win32kbase!DirectComposition::CDesktopTargetMarshaler::_allocate                         - DCOMPOSITIONTAG_DESKTOPTARGETMARSHALERMONITORS\r\n",
  "PDss": " nt!po        - Po device system state\r\n",
  "InF2": " tcpip.sys    - Inet Generic Fixed Size Block pool 2\r\n",
  "InF1": " tcpip.sys    - Inet Generic Fixed Size Block pool 1\r\n",
  "InF0": " tcpip.sys    - Inet Generic Fixed Size Block pool 0\r\n",
  "Mn0E": " monitor.sys  - Buffer for E-EDID v.1.x base block, if any, populated by miniport\r\n",
  "Idpc": " tcpip.sys    - IPsec DoS Protection pacer create\r\n",
  "Mn0F": " monitor.sys  - Buffer for E-EDID v.1.x extension block(s), if any, populated by miniport\r\n",
  "Mn0A": " monitor.sys  - Registry subkey info buffer\r\n",
  "Mn0C": " monitor.sys  - Cached supported monitor frequency ranges WMI data block (overrides from registry)\r\n",
  "Mn0B": " monitor.sys  - Registry value buffer\r\n",
  "Lr??": " <unknown>    -     Buffers used for FsControlFile APIs\r\n",
  "SWbr": " <unknown>    -         bus reference\r\n",
  "svxv": " svhdxflt.sys -         VHDMP/SVHDX interaction\r\n",
  "Vi25": " dxgmms2.sys  - Video memory manager DMA buffer patch location list\r\n",
  "Dlmp": " <unknown>    - Video utility library for Vista display drivers\r\n",
  "SWbi": " <unknown>    -         bus ID\r\n",
  "MuMc": " mup.sys      - Master context\r\n",
  "VoSd": " volsnap.sys  -      Diff area volume allocations\r\n",
  "FSel": " nt!fsrtl     - File System Run Time Extra Create Parameter List\r\n",
  "IcpP": " <unknown>    - NPAGED_LOOKASIDE_LIST I/O completion per processor lookaside pointers\r\n",
  "FSeh": " nt!fsrtl     - File System Run Time Extra Create Parameter Entry\r\n",
  "SD  ": " smbdirect.sys - SMB Direct allocations\r\n",
  "Gh?B": " win32k.sys                           - GDITAG_HMGR_HLSURF_TYPE\r\n",
  "UdAE": " tcpip.sys    - UDP Activate Endpoints\r\n",
  "TpWo": " nt!ex        - Threadpool worker factory objects\r\n",
  "svxi": " svhdxflt.sys -         Instance context\r\n",
  "HcBm": " hcaport.sys - HCAPORT_TAG_BITMAP\r\n",
  "TmPe": " nt!tm        - Tm Enlistment Pointers\r\n",
  "DCdf": " win32kbase!DirectComposition::CSharedReadDesktopTargetMarshaler::_allocate               - DCOMPOSITIONTAG_SHAREDREADDESKTOPTARGETMARSHALER\r\n",
  "VcCh": " rdpdr.sys - Dynamic Virtual channel object\r\n",
  "MmRe": " nt!mm        - ASLR relocation blocks\r\n",
  "PpEL": " nt!pnp       - PNP_DEVICE_EVENT_LIST_TAG\r\n",
  "PmTE": " partmgr.sys  - Partition Manager table entry\r\n",
  "PpEB": " nt!pnp       - PNP_POOL_EVENT_BUFFER\r\n",
  "MmRl": " nt!mm        - temporary readlists for file prefetch\r\n",
  "ObRt": " nt!ob        - object reference stack tracing\r\n",
  "DUQD": " mpsdrv.sys   - MPSDRV upcall user request\r\n",
  "MmRp": " nt!mm        - Mm repurpose logging\r\n",
  "svxc": " svhdxflt.sys -         CDB (SCSI) operations\r\n",
  "DCde": " win32kbase!DirectComposition::CDesktopTargetMarshaler::_allocate                         - DCOMPOSITIONTAG_DESKTOPTARGETMARSHALER\r\n",
  "MmRw": " nt!mm        - Mm read write virtual memory buffers\r\n",
  "UHFF": " win32k.sys                           - GDITAG_UMFD_HFF\r\n",
  "Ntf9": " ntfs.sys     -     Large Temporary Buffer\r\n",
  "TcLW": " tcpip.sys    - TCP Listener Work Queue Contexts\r\n",
  "Qpdg": " <unknown>    -      Debug\r\n",
  "UshR": " win32k!AllocateHidProcessRequest     - USERTAG_HIDPROCREQUEST\r\n",
  "Icp ": " <unknown>    - I/O completion packets queue on a completion ports\r\n",
  "LeGe": " tcpip.sys    - Legacy Registry Mapping Module Buffers\r\n",
  "svxf": " svhdxflt.sys -         File contexts\r\n",
  "Mn05": " monitor.sys  - Cached monitor basic display parameters WMI data block\r\n",
  "Mn04": " monitor.sys  - Cached monitor ID WMI data block\r\n",
  "Mn07": " monitor.sys  - Cached monitor digitial video input parameters WMI data block\r\n",
  "Mn06": " monitor.sys  - Cached monitor analog video input parameters WMI data block\r\n",
  "Mn01": " monitor.sys  - ACPI method evaluation output buffer\r\n",
  "VuCH": " vuc.sys       - Virtual Machine USB Connector Driver (connector handle)\r\n",
  "Mn03": " monitor.sys  - Raw E-EDID v.1.x byte stream including base block + extension blocks (if any)\r\n",
  "Mn02": " monitor.sys  - Unused\r\n",
  "V2rv": " vhdmp.sys    - VHD2 reserved VA mapping\r\n",
  "Mn09": " monitor.sys  - Cached supported monitor source modes WMI data block\r\n",
  "Mn08": " monitor.sys  - Cached monitor color characteristics WMI data block\r\n",
  "TmPx": " nt!tm        - Tm Protocol Array\r\n",
  "MNFs": " msnfsflt.sys - NFS FS Filter, general string buffer\r\n",
  "DEla": " devolume.sys - Drive extender log mini chunk array\r\n",
  "EQHp": " tcpip.sys    - EQoS HKE parameters\r\n",
  "MNFv": " msnfsflt.sys - NFS FS Filter, volume name buffer\r\n",
  "UsDc": " win32k!NtUserDisplayConfigSetDeviceInfo - USERTAG_DISPLAYCONFIG\r\n",
  "AtmT": " <unknown>    - Atom tables\r\n",
  "MSvs": " refs.sys     - Minstore valid/invalid checksum debug buffers (debug only)\r\n",
  "PSC0": " <unknown>    - NDIS Request\r\n",
  "PSC1": " <unknown>    - GPC Client Vc\r\n",
  "IpOl": " tcpip.sys    - IP Offload Log data\r\n",
  "PSC4": " <unknown>    - WMI\r\n",
  "MSvu": " refs.sys     - Minstore volume/instance object\r\n",
  "EQHb": " tcpip.sys    - EQoS HKE binding\r\n",
  "NEWI": " newt_ndis6.sys - NEWT Work Item\r\n",
  "Pctw": " pacer.sys    - PACER Timer Wheels\r\n",
  "MNFf": " msnfsflt.sys - NFS FS Filter, filename buffer\r\n",
  "FDat": " win32k.sys                           - GDITAG_UMFD_GLYPHATTRS\r\n",
  "LBgb": " <unknown>    -     GetBackupList request\r\n",
  "MNFi": " msnfsflt.sys - NFS FS Filter, instance name buffer\r\n",
  "AtmA": " <unknown>    - Atoms\r\n",
  "NtFF": " ntfs.sys     -     FileInfo.c\r\n",
  "FatF": " fastfat.sys  - Fat Fcbs\r\n",
  "MNFS": " msnfsflt.sys - NFS FS Filter, stream context\r\n",
  "Vi59": " dxgmms2.sys  - Video memory manager deferred unlock\r\n",
  "MNFT": " msnfsflt.sys - NFS FS Filter, thread array\r\n",
  "Vi50": " dxgmms2.sys  - Video memory manager physical adapter\r\n",
  "Vi51": " dxgmms2.sys  - Video memory manager set VPR work item\r\n",
  "Vi52": " dxgmms2.sys  - Video memory manager paging history\r\n",
  "Vi53": " dxgmms2.sys  - Video memory manager page table\r\n",
  "Vi54": " dxgmms2.sys  - Video memory manager PTE array\r\n",
  "Vi55": " dxgmms2.sys  - Video memory manager VA range\r\n",
  "Vi56": " dxgmms2.sys  - Video memory manager page directory\r\n",
  "Vi57": " dxgmms2.sys  - Video memory manager PDE array\r\n",
  "MNFC": " msnfsflt.sys - NFS FS Filter, callback context\r\n",
  "DEli": " devolume.sys - Drive extender disk set id record: DEVolume!DiskSetIdentificationRecord\r\n",
  "CMRm": " nt!cm        - Configuration Manager Resource Manager Tag\r\n",
  "MePr": " <unknown>    - In-memory print buffer\r\n",
  "MNFF": " msnfsflt.sys - NFS FS Filter, file context\r\n",
  "Uswt": " win32k!xxxUserNotifyProcessCreate    - USERTAG_WOWTHREADINFO\r\n",
  "MNFI": " msnfsflt.sys - NFS FS Filter, instance context\r\n",
  "DcbC": " msdcb.sys    - DCB NMR provider context\r\n",
  "SDi ": " smbdirect.sys - SMB Direct buffer registrations\r\n",
  "TtcN": " <unknown>    - TTCP NPIs\r\n",
  "Udfl": " udfs.sys     - Udfs Lcb\r\n",
  "SCS4": " <unknown>    -  SCM Microsystems pcmcia reader\r\n",
  "MSdd": " refs.sys     - Minstore director row data\r\n",
  "DElm": " devolume.sys - Drive extender log manager: DEVolume!LogManager\r\n",
  "MSdg": " refs.sys     - Minstore debug\r\n",
  "VmP1": " volmgrx.sys  - Small packets\r\n",
  "UMD?": " WUDFRd.sys   - UMDF pool allocation\r\n",
  "SDg ": " smbdirect.sys - SMB Direct data transfer packet buffers\r\n",
  "DcbG": " msdcb.sys    - DCB string data\r\n",
  "PSCb": " <unknown>    - CallParameters\r\n",
  "PSCc": " <unknown>    - PipeContext\r\n",
  "NtFH": " ntfs.sys     -     SelfHeal.c\r\n",
  "PSCa": " <unknown>    - Adapter\r\n",
  "PSCf": " <unknown>    - Adapter Profile\r\n",
  "PSCg": " <unknown>    - Component\r\n",
  "PSCd": " <unknown>    - FlowContext\r\n",
  "MSds": " refs.sys     - Minstore debug stack logs\r\n",
  "TMtb": " dxgkrnl!CLegacyTokenBuffer::TokenBlock::Create        - TOKENMANAGER_TOKENBLOCK\r\n",
  "PXk": " ndproxy.sys - PX_TRANSLATE_SAP_TAG\r\n",
  "WanM": " <unknown>    - Connection Table\r\n",
  "DElp": " devolume.sys - Drive extender logical to physical request: DEVolume!LogicalToPhysicalRequest\r\n",
  "NvLp": " <nvlddmkm.sys> - nVidia video driver\r\n",
  "Sis ": " <unknown>    - Single Instance Store (dd\\sis\\filter)\r\n",
  "DCtg": " win32kbase!DirectComposition::CTransformGroupMarshaler::_allocate                        - DCOMPOSITIONTAG_TRANSFORMGROUPMARSHALER\r\n",
  "DElr": " devolume.sys - Drive extender log reader: DEVolume!LogReader\r\n",
  "GVdv": " win32k.sys                           - GDITAG_VDEV\r\n",
  "Wdog": " watchdog.sys - Watchdog object/context allocation\r\n",
  "ATon": " AppTag object name\r\n",
  "Vi5b": " dxgmms2.sys  - Video memory manager partition\r\n",
  "Vi5c": " dxgmms2.sys  - Video memory manager partition adapter info\r\n",
  "Vi5d": " dxgmms2.sys  - Video memory manager cross adapter alloc\r\n",
  "LBxp": " <unknown>    -     Transport\r\n",
  "Vi5f": " dxgmms2.sys  - Video scheduler async operation\r\n",
  "FatV": " fastfat.sys  - Fat Vcb stat bucket\r\n",
  "SeDt": " nt!se        - Security Global Singleton attributes table\r\n",
  "RxSo": " rdbss.sys - RDBSS SrvOpen\r\n",
  "WanR": " <unknown>    - WanPacket\r\n",
  "WofI": " wof.sys      - Wof inflate buffer\r\n",
  "UlWI": " http.sys     - Work Item\r\n",
  "WofD": " wof.sys      - Wof directory buffer\r\n",
  "Txte": " ntfs.sys     - TXF_RMCB_TABLE_ENTRY\r\n",
  "WofF": " wof.sys      - Wof file context\r\n",
  "FatT": " fastfat.sys  - Fat directory allocation bitmaps\r\n",
  "UlWC": " http.sys     - Work Context\r\n",
  "Txtc": " ntfs.sys     - TXF_TRANS_CANCEL_LIST_ENTRY\r\n",
  "LSRp": " srv2.sys     -     SRVLIB reparse point\r\n",
  "Psta": " nt!ps        - Power management system state\r\n",
  "DEsh": " devolume.sys - Drive extender space holder operation: DEVolume!SpaceHolderOperation\r\n",
  "SeDb": " nt!se        - Temp directory query buffer to delete logon session symbolic links\r\n",
  "PXb": " ndproxy.sys - PX_TAPILINE_TAG\r\n",
  "DEsd": " devolume.sys - Drive extender disk set disk: DEVolume!DiskSetDisk\r\n",
  "WofV": " wof.sys      - Wof volume context\r\n",
  "DEsg": " devolume.sys - Drive extender disk set globals: DEVolume!DEDiskSetGlobals\r\n",
  "DCna": " win32kbase!DirectComposition::CNaturalAnimationMarshaler::_allocate                      - DCOMPOSITIONTAG_NATURALANIMATIONMARSHALER\r\n",
  "PXa": " ndproxy.sys - PX_ENUMLINE_TAG\r\n",
  "DEsb": " devolume.sys - Drive extender super block buffer\r\n",
  "smDS": " nt!store     -         ReadyBoost cache file SID\r\n",
  "DChc": " win32kbase!DirectComposition::CHolographicCompositionMarshaler::_allocate                - DCOMPOSITIONTAG_HOLOGRAPHICCOMPOSITIONMARSHALER\r\n",
  "CM??": " nt!cm        - Internal Configuration manager allocations\r\n",
  "DcbU": " msdcb.sys    - DCB UQOS_POLICY_DESCRIPTOR\r\n",
  "Woff": " wof.sys      - Wof extended file context\r\n",
  "BthS": " bthport.sys  - Bluetooth port driver (security)\r\n",
  "IUcp": " <unknown>    -     completion port minipackets\r\n",
  "NEFT": " newt_ndis6.sys - NEWT Filter Object\r\n",
  "smDt": " nt!store or rdyboost.sys - ReadyBoost store debug trace buffer\r\n",
  "DbLo": " <unknown>    - Debug logging\r\n",
  "Udfp": " udfs.sys     - Udfs Pcb\r\n",
  "TcCT": " tcpip.sys    - TCP Connection Tuples\r\n",
  "VmbK": " kmcl.lib        - Virtual Machine Bus Kernel Mode Client Library\r\n",
  "MCDx": " <unknown>    - OpenGL MCD server (mcdsrv32.dll) allocations\r\n",
  "DEmc": " devolume.sys - Drive extender volume chunk init mapping manager: DEVolume!VolumeChunkInitializationMappingManager\r\n",
  "TmTx": " nt!tm        - Tm KTRANSACTION object\r\n",
  "DEml": " devolume.sys - Drive extender log mapping manager: DEVolume!LogMappingManager\r\n",
  "DCtx": " win32kbase!DirectComposition::CSpatialRemarshalerMarshaler::_allocate                    - DCOMPOSITIONTAG_SPATIALREMARSHALERMARSHALER\r\n",
  "I6bf": " tcpip.sys    - IPv6 Generic Buffers (Source Address List allocations)\r\n",
  "Cdpn": " cdfs.sys     - CDFS Prefix Entry name\r\n",
  "DEmv": " devolume.sys - Drive extender volume mapping manager: DEVolume!VolumeMappingManager\r\n",
  "Usvc": " win32k!_GetPointerDeviceProperties   - USERTAG_VALUECAP\r\n",
  "NDw3": " ndis.sys     - NDIS_TAG_WMI_EVENT_ITEM\r\n",
  "IdeX": " <unknown>    - PCI IDE\r\n",
  "DEms": " devolume.sys - Drive extender superblock mapping manager: DEVolume!SuperBlockMappingManager\r\n",
  "UlSC": " http.sys     - SSL Cert Data\r\n",
  "MCDd": " <unknown>    - OpenGL MCD driver (embedded in a display driver like s3mvirge.dll)\r\n",
  "ND  ": " ndis.sys     - general NDIS allocations\r\n",
  "Usvi": " win32k!ResizeVisExcludeMemory        - USERTAG_VISRGN\r\n",
  "IdeP": " <unknown>    - atapi IDE\r\n",
  "WanQ": " <unknown>    - DataBuffer\r\n",
  "Gfil": " win32k.sys                           - GDITAG_MAPFILE\r\n",
  "IpLA": " ipsec.sys    -  lookaside lists\r\n",
  "DCtt": " win32kbase!DirectComposition::CTranslateTransformMarshaler::_allocate                    - DCOMPOSITIONTAG_TRANSLATETRANSFORMMARSHALER\r\n",
  "Ref?": " refs.sys     -     Unkown allocation\r\n",
  "IoTt": " nt!vf        - I/O verifier IRP tracking table\r\n",
  "Pool": " <unknown>    - Pool tables, etc.\r\n",
  "BTME": " bthenum.sys  - Bluetooth enumerator\r\n",
  "DCsv": " win32kbase!DirectComposition::CSpriteVisualMarshaler::_allocate                          - DCOMPOSITIONTAG_SPRITEVISUALMARSHALER\r\n",
  "RfCN": " rfcomm.sys   -   RFCOMM connect\r\n",
  "IoTi": " nt!io        - Io timers\r\n",
  "DCsw": " win32kbase!DirectComposition::CCompositionSurfaceWrapperMarshaler::_allocate             - DCOMPOSITIONTAG_SURFACEWRAPPERMARSHALER\r\n",
  "gFil": " <unknown>    -     Gdi FILEVIEW\r\n",
  "dFVE": " dumpfve.sys  - Full Volume Encryption crash dump filter (Bitlocker Drive Encryption)\r\n",
  "BTMO": " bthmodem.sys - Bluetooth modem\r\n",
  "RfCH": " rfcomm.sys   -   RFCOMM channel\r\n",
  "StFc": " netio.sys    - WFP stream filter conditions\r\n",
  "RxSy": " rdbss.sys - RDBSS symlink\r\n",
  "VRes": " nt!Vf        - Deadlock Verifier resources\r\n",
  "PdcP": " pdc.sys      - PDC_PORT_TAG\r\n",
  "PdcS": " pdc.sys      - PDC_SUSPRES_TAG\r\n",
  "PdcR": " pdc.sys      - PDC_RESILIENCY_TAG, RESILIENCY_CLIENT_TAG\r\n",
  "PpTt": " mpsdrv.sys   - MPSDRV PPTP TCP analyzer\r\n",
  "PdcT": " pdc.sys      - PDC_TOKEN_TAG\r\n",
  "PdcI": " pdc.sys      - PDC_INCLUSION_LIST_TAG\r\n",
  "PdcM": " pdc.sys      - PDC_MESSAGE_TAG\r\n",
  "PdcN": " pdc.sys      - PDC_NOTIFICATION_TAG, NOTIFICATION_CLIENT_TAG\r\n",
  "PdcA": " pdc.sys      - PDC_ACTIVATION_TAG, ACTIVATOR_CLIENT_TAG\r\n",
  "PdcC": " pdc.sys      - PDC_CLIENT_PORT_TAG\r\n",
  "PdcE": " pdc.sys      - ACTIVATOR_EVENT_TAG\r\n",
  "PpTg": " mpsdrv.sys   - MPSDRV PPTP GRE analyzer\r\n",
  "MmLn": " nt!mm        - temporary name buffer for driver loads\r\n",
  "WPDV": " BasicRender.sys - Basic Render DX Device\r\n",
  "AlIn": " nt!alpc      - ALPC Internal allocation\r\n",
  "PPMd": " <unknown>    - Processor Drivers (Processor Power Management).\r\n",
  "LSwn": " srv.sys      -     SMB1 normal work context\r\n",
  "CDmp": " crashdmp.sys - Crashdump driver\r\n",
  "ScRV": " <unknown>    -      Volume entry\r\n",
  "Gila": " win32kbase.sys                       - GDITAG_ISOLATED_LOOKASIDE_LIST_ALLOCATION\r\n",
  "TQoS": " tcpip.sys    - TL QoS Client Data\r\n",
  "PPMp": " nt!po        - Processor Power Manager Perf States\r\n",
  "PPMw": " nt!po        - Processor Power Manager WMI Interface\r\n",
  "UdpH": " tcpip.sys    - UDP Headers\r\n",
  "UlOR": " http.sys     - Owner RefTrace Signature\r\n",
  "RTLF": " mpsdrv.sys   - MPSDRV filter\r\n",
  "Udwp": " win32kbase!SetMonitorData            - USERTAG_REFCOUNTED_DPI_INFORMATION\r\n",
  "Fatv": " fastfat.sys  - Fat backpocket Vpb\r\n",
  "PfFH": " nt!pf        - Pf RpContext FileKeyHash buckets\r\n",
  "PfFK": " nt!pf        - Pf RpContext FileKeyHashEntry\r\n",
  "ObjT": " nt!ob        - object type objects\r\n",
  "Mmww": " nt!mm        - Write watch bitmap VAD info\r\n",
  "Txfq": " ntfs.sys     - Txf quota block\r\n",
  "HdCl": " <unknown>    - HID Client Sample Driver\r\n",
  "FMus": " fltmgr.sys   -       Unicode string\r\n",
  "ScC2": " classpnp.sys -  PDO relations\r\n",
  "AzPd": " HDAudio.sys  - HD Audio Class Driver (AzDma)\r\n",
  "SrTI": " sr.sys       -         Directory delete information\r\n",
  "Txfi": " ntfs.sys     - TXF_FCB_INFO\r\n",
  "Dxga": " <unknown>    - XGA video driver\r\n",
  "Txfo": " ntfs.sys     - TXF_FO\r\n",
  "Txfl": " ntfs.sys     - TXF_FCB_CLEANUP\r\n",
  "Txfc": " ntfs.sys     - TXF_FCB\r\n",
  "Refv": " refs.sys     -     COMPRESSION_SYNC\r\n",
  "Mm  ": " nt!mm        - general Mm Allocations\r\n",
  "Txfe": " ntfs.sys     - TXF_FCB_EXTENSION\r\n",
  "CMNb": " nt!cm        - Configuration Manager Name Tag\r\n",
  "vTDR": " dxgkrnl.sys  - Video timeout detection/recovery\r\n",
  "Gdbr": " win32k!BRUSHOBJ_pvAllocRbrush        - GDITAG_RBRUSH\r\n",
  "Txts": " ntfs.sys     - TXF_TRANS_SYNC\r\n",
  "DCet": " win32kbase!DirectComposition::CCompiledEffectTemplate::_allocate                         - DCOMPOSITIONTAG_COMPILEDEFFECTTEMPLATEMARSHALER\r\n",
  "DCev": " win32kbase!DirectComposition::CEvent::_allocate                                          - DCOMPOSITIONTAG_EVENT\r\n",
  "Vrdt": " netvsc60.sys - Virtual Machine Network VSC Driver (NDIS 6, RNDIS miniport driver library, chimney TCP context)\r\n",
  "ScC1": " classpnp.sys -  Registry path buffer\r\n",
  "DCsc": " win32kbase!DirectComposition::CSystemChannel::_allocate                                  - DCOMPOSITIONTAG_SYSTEMCHANNEL\r\n",
  "Nb35": " netbt.sys    - NetBT registry data\r\n",
  "LBpt": " <unknown>    -     Paged transport\r\n",
  "Nb37": " netbt.sys    - NetBT lmhosts path\r\n",
  "Nb36": " netbt.sys    - NetBT string\r\n",
  "Nb31": " netbt.sys    - NetBT configuration entry\r\n",
  "Nb30": " netbt.sys    - NetBT registry string\r\n",
  "Nb33": " netbt.sys    - NetBT registry data\r\n",
  "smVc": " rdyboost.sys -         ReadyBoost read verification buffer\r\n",
  "DCef": " win32kbase!DirectComposition::CCompiledEffect::_allocate                                 - DCOMPOSITIONTAG_COMPILEDEFFECTMARSHALER\r\n",
  "Vrdc": " netvsc60.sys - Virtual Machine Network VSC Driver (NDIS 6, RNDIS miniport driver library, chimney neighbor or path context)\r\n",
  "Nb39": " netbt.sys    - NetBT file objects\r\n",
  "Nb38": " netbt.sys    - NetBT string\r\n",
  "DxgK": " dxgkrnl.sys  - Vista display driver support\r\n",
  "WPRC": " BasicRender.sys - Basic Render Rectangles (for Present)\r\n",
  "MmSb": " nt!mm        - Mm subsections\r\n",
  "MmSa": " nt!mm        - Subsection AVL tree allocations\r\n",
  "MmSg": " nt!mm        - Mm segments\r\n",
  "MmSe": " nt!mm        - Mm secured VAD allocation\r\n",
  "McaD": " hal.dll      - HAL MCA Driver Log\r\n",
  "McaK": " hal.dll      - HAL MCA Kernel Log\r\n",
  "MmSi": " nt!mm        - Control area security image stubs\r\n",
  "NDif": " ndis.sys     - NDIS_TAG_IF\r\n",
  "PmSD": " partmgr.sys  - Partition Manager snapshot data cache\r\n",
  "MmSm": " nt!mm        - segments used to map data files\r\n",
  "werk": " <unknown>    - WER kernel mode reporting allocation\r\n",
  "LShs": " srv2.sys     -     SMB2 lease hash table\r\n",
  "McaP": " hal.dll      - HAL MCA Log from previous boot\r\n",
  "MmSw": " nt!mm        - Store write support when prefetching\r\n",
  "PcSl": " <unknown>    - WDM audio stuff\r\n",
  "McaT": " hal.dll      - HAL MCA temporary Log\r\n",
  "MmSy": " nt!mm        - Mm PTE and IO tracking logs\r\n",
  "RX00": " <unknown>    - ATI video driver\r\n",
  "InSB": " tcpip.sys    - Inet stack block\r\n",
  "InSC": " tcpip.sys    - Inet Queued Send Contexts\r\n",
  "Dps5": " <unknown>    - NT5 PostScript printer driver\r\n",
  "NtFs": " ntfs.sys     -     StrucSup.c\r\n",
  "dfsr": " <unknown>    - RDBSS IRP allocation\r\n",
  "MmSP": " nt!mm        - SLIST entries for system PTE NB queues\r\n",
  "MmSW": " nt!mm        - Store write support\r\n",
  "TcOD": " tcpip.sys    - TCP Offload Devices\r\n",
  "Se  ": " nt!se        - General security allocations\r\n",
  "FDtl": " win32k.sys                           - GDITAG_UMFD_TLS\r\n",
  "Gelt": " win32k!EntryDataLookupTable::Create  - GDITAG_ENTRY_DATA_LOOKUP_TABLE\r\n",
  "InNA": " <unknown>    - Inet Na Clients\r\n",
  "Viac": " dxgmms2.sys  - GPU scheduler hardware context\r\n",
  "PX7": " ndproxy.sys - PX_COCALLPARAMS_TAG\r\n",
  "UlIR": " http.sys     - Internal Response\r\n",
  "Pcsb": " pacer.sys    - PACER Send Buffers\r\n",
  "RefT": " <unknown>    - Bluetooth reference tracking\r\n",
  "DCey": " win32kbase!DirectComposition::CEllipseGeometryMarshaler::_allocate                       - DCOMPOSITIONTAG_ELLIPSEGEOMETRYMARSHALER\r\n",
  "Gelc": " win32k!EntryDataLookupTable::Initialize - GDITAG_ENTRY_DATA_LOOKUP_TABLE_COLUMN\r\n",
  "UdSM": " tcpip.sys    - UDP Send Messages Requests\r\n",
  "AzFg": " HDAudio.sys  - HD Audio Class Driver (Audio Function Group)\r\n",
  "Vi45": " dxgmms2.sys  - Video memory manager CPU host aperture\r\n",
  "RefH": " refs.sys     -     SCB_SNAPSHOT\r\n",
  "MSal": " refs.sys     - Minstore allocator block\r\n",
  "Pf??": " nt!pf        - Pf Allocations\r\n",
  "MmEx": " nt!mm        - Mm events\r\n",
  "Gala": " win32k.sys                           - GDITAG_ADAPTER_LUID_ARRAY\r\n",
  "Dpsi": " <unknown>    - psidisp video driver\r\n",
  "Dpsh": " <unknown>    - Postcript driver heap memory\r\n",
  "Dpsm": " <unknown>    - Postcript driver memory\r\n",
  "knlf": " win32k.sys                           - GDITAG_FONT_LINK\r\n",
  "MSeg": " nt!mm        - segments used to support image files\r\n",
  "MSeb": " refs.sys     - Minstore embedded factory (B+ and associated)\r\n",
  "Rnmr": " rndismp.sys  - RNDIS MP driver receive frame\r\n",
  "Vmsc": " storchannel.lib - Virtual Machine Storage VSC Channel Library\r\n",
  "HT14": " <unknown>    - GDI Halftone CalculateStretch() for InputSI/pSrcMaskLine\r\n",
  "ReTc": " refs.sys     -     FILE_LEVEL_TRIM_CONTEXT\r\n",
  "ReTa": " <unknown>    - Resource Extended Table\r\n",
  "UsKm": " win32k!DriverEntry                   - USERTAG_KMUTEX\r\n",
  "ReTe": " refs.sys     -     ReFS Telemetry\r\n",
  "Lr2x": " <unknown>    -     Transact SMB context\r\n",
  "ReTm": " refs.sys     -     DEVICE_MANAGE_DATA_SET_ATTRIBUTES RefsDeviceManageDataSetAttributesLookasideList\r\n",
  "PsLd": " nt!ps        - Process LDT information blocks\r\n",
  "ReTr": " <unknown>    - Per ETHREAD EXECUTIVE Resource tracking.\r\n",
  "UsKs": " win32k!CreateKernelSemaphore         - USERTAG_KSEMAPHORE\r\n",
  "Rnmt": " rndismp.sys  - RNDIS MP driver timer\r\n",
  "UsKt": " win32k!RemoteConnect                 - USERTAG_KTIMER\r\n",
  "UsKw": " win32k!xxxDesktopThread              - USERTAG_KWAITBLOCK\r\n",
  "Usd1": " win32k!FreeListAdd                   - USERTAG_DDE1\r\n",
  "LS18": " srvnet.sys   -     SRVNET LookasideList level 18 allocation 704K Bytes\r\n",
  "LS19": " srvnet.sys   -     SRVNET LookasideList level 19 allocation 768K Bytes\r\n",
  "PSPi": " pshed.dll    - PSHED Plug-in\r\n",
  "UlDR": " http.sys     - Deferred Remove Item\r\n",
  "LS10": " srvnet.sys   -     SRVNET LookasideList level 10 allocation 192K Bytes\r\n",
  "LS11": " srvnet.sys   -     SRVNET LookasideList level 11 allocation 256K Bytes\r\n",
  "LS12": " srvnet.sys   -     SRVNET LookasideList level 12 allocation 320K Bytes\r\n",
  "LS13": " srvnet.sys   -     SRVNET LookasideList level 13 allocation 384K Bytes\r\n",
  "LS14": " srvnet.sys   -     SRVNET LookasideList level 14 allocation 448K Bytes\r\n",
  "LS15": " srvnet.sys   -     SRVNET LookasideList level 15 allocation 512K Bytes\r\n",
  "LS16": " srvnet.sys   -     SRVNET LookasideList level 16 allocation 576K Bytes\r\n",
  "LS17": " srvnet.sys   -     SRVNET LookasideList level 17 allocation 640K Bytes\r\n",
  "CSdk": " <unknown>    - Cluster Disk Filter driver\r\n",
  "Pwff": " pacer.sys    - PACER WFP Filters\r\n",
  "DCmb": " win32kbase!DirectComposition::CSharedManipulationTransformMarshaler::_allocate           - DCOMPOSITIONTAG_SHAREDMANIPULATIONTRANSFORMMARSHALER\r\n",
  "PX8": " ndproxy.sys - PX_REQUEST_TAG\r\n",
  "VuCW": " vuc.sys       - Virtual Machine USB Connector Driver (WDF)\r\n",
  "Vi49": " dxgmms2.sys  - Video memory manager GPU VA\r\n",
  "Vi48": " dxgmms2.sys  - Video memory manager paging queue\r\n",
  "VNC ": " netvsc50.sys/netvsc60.sys - Virtual Machine Network VSC Driver\r\n",
  "VuCP": " vuc.sys       - Virtual Machine USB Connector Driver (virtual hub ports)\r\n",
  "Vi43": " dxgmms2.sys  - Video memory manager async operation\r\n",
  "Vfwi": " nt!Vf        - IO_WORKITEM allocated by I/O verifier version of IoAllocateWorkItem\r\n",
  "Vi41": " dxgmms2.sys  - Video memory manager process budget info\r\n",
  "UlDT": " http.sys     - Debug Thread Pool\r\n",
  "Vi47": " dxgmms2.sys  - Video memory manager worker thread\r\n",
  "Vi46": " dxgmms2.sys  - Video memory manager CPU host aperture page\r\n",
  "HcEv": " hcaport.sys - HCAPORT_TAG_EVENT\r\n",
  "Vi44": " dxgmms2.sys  - Video memory manager fence storage\r\n",
  "RAWb": " nt!RAW       - RAW file system buffer\r\n",
  "Refq": " refs.sys     -     General Allocation with Quota\r\n",
  "RfPP": " rfcomm.sys   -   RFCOMM pnp\r\n",
  "HcEn": " hcaport.sys - HCAPORT_TAG_ENUM\r\n",
  "SDh ": " smbdirect.sys - SMB Direct FRMR objects\r\n",
  "Cc  ": " nt!cc        - Cache Manager allocations (catch-all)\r\n",
  "FatC": " fastfat.sys  - Fat Ccbs\r\n",
  "FatB": " fastfat.sys  - Fat allocation bitmaps\r\n",
  "Lr  ": " <unknown>    -     Generic allocations\r\n",
  "DElb": " devolume.sys - Drive extender log buffer\r\n",
  "I4ma": " tcpip.sys    - IPv4 Local Multicast Addresses\r\n",
  "FatE": " fastfat.sys  - Fat EResources\r\n",
  "FatD": " fastfat.sys  - Fat pool dirents\r\n",
  "Gfcb": " <unknown>    - EXIFS Grow FCB\r\n",
  "TSrp": " termdd.sys   - Terminal Services - RP_ALLOC_TAG\r\n",
  "FatI": " fastfat.sys  - Fat IrpContexts\r\n",
  "FatO": " fastfat.sys  - Fat I/O buffer\r\n",
  "FatN": " fastfat.sys  - Fat Nonpaged Fcbs\r\n",
  "Usws": " win32kfull!xxxCreateWindowEx         - USERTAG_WND_SERVER_EXTRA_BYTES\r\n",
  "FatL": " fastfat.sys  - Fat FAT entry lookup buffer on verify\r\n",
  "FatS": " fastfat.sys  - Fat stashed Bpb\r\n",
  "FatR": " fastfat.sys  - Fat repinned Bcb\r\n",
  "FatQ": " fastfat.sys  - Fat buffered user buffer\r\n",
  "FatP": " fastfat.sys  - Fat output for query retrieval pointers (caller frees)\r\n",
  "FatW": " fastfat.sys  - Fat FAT windowing structure\r\n",
  "MXF ": " <unknown>    - DirectMusic (MIDI Transform Filter)\r\n",
  "DElw": " devolume.sys - Drive extender log writer buffer: DEVolume!LogWriterBuffer\r\n",
  "I6aa": " tcpip.sys    - IPv6 Local Anycast Addresses\r\n",
  "V2wi": " vhdmp.sys    - VHD2 work item\r\n",
  "Uswd": " win32k!xxxCreateWindowEx             - USERTAG_WINDOW\r\n",
  "FatX": " fastfat.sys  - Fat IO contexts\r\n",
  "SmCe": " mrxsmb.sys    - SMB connection object\r\n",
  "Uswc": " win32k!SetSwapChainProp              - USERTAG_SWAPCHAIN\r\n",
  "I6ai": " tcpip.sys    - IPv6 Local Address Identifiers\r\n",
  "Ref9": " refs.sys     -     Large Temporary Buffer\r\n",
  "Fatb": " fastfat.sys  - Fat Bcb arrays\r\n",
  "UlCI": " http.sys     - Config Group URL Info\r\n",
  "Fatf": " fastfat.sys  - Fat deferred flush contexts\r\n",
  "Fate": " fastfat.sys  - Fat EA set headers\r\n",
  "Fatd": " fastfat.sys  - Fat EA data\r\n",
  "Ref0": " refs.sys     -     General pool allocation\r\n",
  "Fati": " fastfat.sys  - Fat IO run descriptor\r\n",
  "IoUs": " nt!io        - I/O SubSystem completion Context Allocation\r\n",
  "Fatn": " fastfat.sys  - Fat filename buffer\r\n",
  "LBdi": " <unknown>    -     POOL_DOMAIN_INFO\r\n",
  "Fats": " fastfat.sys  - Fat verification-time boot sector\r\n",
  "Fatr": " fastfat.sys  - Fat verification-time rootdir snapshot\r\n",
  "smET": " nt!store or rdyboost.sys - ReadyBoost ETA check work item\r\n",
  "WvCy": " <unknown>    - WDM Audio WaveCyc port\r\n",
  "LBds": " <unknown>    -     Send datagram context\r\n",
  "Fatx": " fastfat.sys  - Fat delayed close contexts\r\n",
  "TmTm": " nt!tm        - Tm KTRANSACTIONMANAGER object\r\n",
  "IoKB": " nt!io        - Registry basic key block (temp allocation)\r\n",
  "TtcC": " <unknown>    - TTCP Controllers\r\n",
  "DCvt": " win32kbase!DirectComposition::CVisualTargetMarshaler::_allocate                          - DCOMPOSITIONTAG_VISUALTARGETMARSHALER\r\n",
  "TmEn": " nt!tm        - Tm KENLISTMENT object\r\n",
  "RefS": " refs.sys     -     SCB_INDEX\r\n",
  "RefR": " refs.sys     -     READ_AHEAD_THREAD\r\n",
  "Nnnn": " netio.sys    - NetIO NetBuffers And NetBufferLists\r\n",
  "Pcwc": " pacer.sys    - PACER WAN NetworkBufferList CTXs\r\n",
  "RefV": " refs.sys     -     VPB\r\n",
  "RefI": " refs.sys     -     IO_CONTEXT\r\n",
  "CMSH": " wibcm.sys - WIBCM_SHARED_TAG\r\n",
  "RefK": " refs.sys     -     KEVENT\r\n",
  "Abos": " <unknown>    - Abiosdsk\r\n",
  "Pfcs": " pacer.sys    - PACER Flow Counter Sets\r\n",
  "RefN": " refs.sys     -     NUKEM\r\n",
  "FxDr": " wdf01000.sys - KMDF driver globals/generic pool allocation tag. Fallback tag in case driver tag is unusable.\r\n",
  "RefC": " refs.sys     -     CCB\r\n",
  "RefE": " refs.sys     -     INDEX_CONTEXT\r\n",
  "FM??": " fltmgr.sys   - Unrecognized FltMgr tag (update pooltag.w)\r\n",
  "RefF": " refs.sys     -     FCB_INDEX\r\n",
  "Refx": " refs.sys     -     General Allocation\r\n",
  "TtcW": " <unknown>    - TTCP Work Items\r\n",
  "Fat ": " fastfat.sys  - Fat File System allocations\r\n",
  "UsEC": " win32k!AddWEFCOMPInvalidateSListEntry - USERTAG_WSEXCOMPINVALID\r\n",
  "PcwI": " nt!pcw       - PCW counter set Instance\r\n",
  "Efst": " <unknown>    -  EXIFS FS Statistics\r\n",
  "UlDO": " http.sys     - Disconnect Object\r\n",
  "Refs": " refs.sys     -     SCB_DATA\r\n",
  "Refr": " refs.sys     -     ERESOURCE\r\n",
  "Refu": " refs.sys     -     NTFS_MARK_UNUSED_CONTEXT\r\n",
  "PcwC": " nt!pcw       - PCW Counter set\r\n",
  "Refw": " refs.sys     -     Workspace\r\n",
  "PcwS": " nt!pcw       - PCW System call buffer\r\n",
  "Refi": " refs.sys     -     IRP_CONTEXT\r\n",
  "Efsm": " <unknown>    - EFS driver\r\n",
  "Refk": " refs.sys     -     FILE_LOCK\r\n",
  "NDMb": " ndis.sys     - NDIS_TAG_MAC_BLOCK\r\n",
  "Refl": " refs.sys     -     LCB\r\n",
  "Refo": " refs.sys     -     SCB_INDEX normalized named buffer\r\n",
  "Refn": " refs.sys     -     SCB_NONPAGED\r\n",
  "TtcM": " <unknown>    - TTCP Mappings\r\n",
  "TtcL": " <unknown>    - TTCP Listeners\r\n",
  "CMSc": " nt!cm        - security cache pooltag\r\n",
  "Efsc": " <unknown>    - EFS driver\r\n",
  "PcwR": " nt!pcw       - PCW provider Registration\r\n",
  "@KCH": " <unknown>    - (Intel video driver) Chipset specific service\r\n",
  "CcMb": " nt!cc        - Cache Manager Mbcb\r\n"
}

EXP_SEARCH_ICON = \
"""R0lGODlhyQDIAHAAACwAAAAAyQDIAIf////v7+/39/fOlAD/73v/94y99//W9//3/++Uxff3zmv/
3nP/3nul1vf378Xe3ta95vfe5ubFlAj396X/3oSMpaWMjJzWzs69vb3395St5vd7lIRzc5xrY5T3
/86tra33zmOcaymUzvfOpTqcnM7enBAQEN4QEJwQpVoQpRCE3qVz3lpz3hBzYzHW5pz/74xjWlrF
xdZzc3P3znMZc1oZUlpzaxCla5Tv9/fe5ntzpVqca85C5lpC5hAQ5loQ5hBzpRClnKXWpVpKa1pr
OhmlOlqlOt6lOpxzEBmlEFqlEN6lEJyE3tal3lql3hDOWs7OWoTOGc7OGYSlnClSteacnHsZteZS
ta0Zta1SlOYZlOZSlK0ZlK1C5uYI5uZC5q0I5q1CMRnWxVr3vVr3pTpCUhlCMVrFexBCc95CMd5C
MZxCcxlCc5xCpXtCpTEQMRkQMVoQMd4QMZwQpXsQpTEQcxkQc94Qc5yl3qVz3ntz3jFCUt5CUpwQ
UhkQUt4QUpycpe+lnFqEe4zFxaXmvRBSUlrW5mPFtRCEa2PvnKVza+/vWhnvWlLvnM7OEFLOEBmc
e2NrY2v35pxza8WElMWca+9C5ntC5jGl3tYQ5nsQ5jFzpTF7pealnAil3nul3jHmexnOWu/OWqXO
Ge/OGaXvWs7vWoTvGc7vGYTvzpzFnJzWxTrOxYTO7xBj5uYp5uZj5q0p5q2cYwjvnHvve1LvnO/F
nO/OMVLOMRnFWhnFWlLvEFLvEBmlcwj39+bFnHvvWu/vWqXvGe/vGaXO70Lmxeb3//+cOilzOmtz
Ou9zOq3v7xCcEClzEGtzEO9zEK1CEClCEGtCEO9CEK1CtVpCtRAQECkQEGucOghzOkpzOs5zOoyc
EAhzEEpzEM5zEIxCEAhCEEpCEM5CEIxClFpClBAQEAgQEEpKUkrFnMXFe0rvMVLvMRmlWmOMY5zF
5s7v70L3rVKE7/drc1rv5ub35u/3zkr/72PF9+/e9+//93u9lAB7xffv3u//3mPv7/cI/wABCBQY
oGCAgQQNIgRg8CDChgsbOkyocKDEiBUtZqQ4kSPGjRc1bmQ4EuLDkihBmuTYMaTIjiQLfoTpMqbM
ly1Xejx58+XMnCqD9rRJM2XRoUR5Dq1Z0+bMp0qBLtXJVKdTpT+jasW51SfWrkm5imXJ80FRsxHN
LlWbU+1JtyLRjk0oV2NdsnanwqV4t2nBuyQBB9hLkO3bqUKPwoxgNOtAxhv7GYzwELLUBwstZy5p
+LFOyQUpW9T8EjNC0p6RVo08+SRj03hje/yXuue/1QWNIRBo+aAA2QwJX/VJW7ZE3bwh/g6bELLA
5VYhFgfQWyDtyRMRXFxOj+pg1QEY//8WsBs07OZFnQ/sHr4fAOgG3Q80f7B4yN8IJIt/X/7vZtbt
vceRfALRB4B9VukXwHj9DYYRY5mBdpAxBPWTDz0EMnShZFH9JRN8AXCoET0XnsReWUfRI9Bu1AVA
IouyVTdXQSeKxBiMMakIAIuMvbjVb/30CJSICZGoY5FD1UNjPjt6RuJyABhjJGJDYRhAPhMOKCBJ
FgZQz0ACQEShQBhiOSZFGQpwIUgKnhZieFFStB9wZQZwZkxprokYljCyRdmYDbkHXZc6sliQZFDi
iRGRsmHZ3ZFS6vnQo0Dl4x4C8HWXKKULSejQbxcZ6uJQegLV3UC70ejbeqN2qhOlUh3/ZGhnSHYU
6akIcdokAFPeGdqH741605eHlggAsQVhiVCYrVY2lJrJPodeS0JuyR6E+IGG4ZZL1mcRiXle+Sl6
qGr4JpRvQihgfAHAaNCFZ2pXEXnGJLtqgQYJgK53a07aLEFCutvQpv5t2c+jC7FXZbIZWlrjtDwd
vJDDMB3sYsImAdmdsgKWelK/IwILpIv5JGrxkVHqKhKjsJ5JokFnbqdRBOEipfCW0D6spsq8iqsi
iHCGDNO1K5IZIpPSeizStvOpOh5DVt5rENOpZcgrlp+mKq6+M9/0m6XhtWvRwcYWaalSKANgMUxY
ArZ2R55KqyrSx6oqq3XJqqgbqPMi/2myQV862ZO86hHkaMkaYSlayNKS9CRCFveDI0JSlgQajsLG
uiuhDl1nFmP1LGfWA/Q84IADkkwgSSqrSyKJAwaNviCMEgoEqEGYryQvzBpdjqpVqCXE4XLMAit8
QQJnVHxuY2Gq6q4kne1mT8TS2vOV9Gj9QAQPdD/YA4OoUsUvIwQywggS7DOA+uxLcMH7MVwQg1lc
96xsn4dmBxqHLEq2prsqq5eHMPK4FbXpIWv73cscQqHu6AeBoTkJaCJiIUEJrlwkkxxYHBWi4j3g
AuETgxDOdwgJHEJ9hxiAClfIwkP8AgMwxMADYiCTg4wqbfcxF4kmJRkCyQtLdGPObv/YY7WpJQxr
gSvS8CC2LmHt6lc5QRhPFsc31YBtImE6GD0uIIlBiMF8UyhBCSXAwjKqMIXsW6EEPsBGGL5jggC4
4pY0JBkcvQ1KHEQaqE72NChCj2ICCZykMIUkX2GtI5DBleEkgzK/KA9qSDGPgCiUuVwNZgQlmIIE
yGjG9XVyfRIowSrEsIAFnDEQQWjj/Lz0D+10Z3HButnSxqUwlFmIPX3UTz+edj1YcimI1xvcyVpy
s8BRCmmUdKK0GKOugbAliVejXo6oJYR9qM+M7EvhAE64zVWsYgGS8IAvEEBOX6xChRKoQhAq8AEZ
Im95jXOJdvSELkkZ00iYsWF46LH/w68YcFTE05Aiq6iswOXNVAtKHKOUpBB3dYmCBZkO1LD2nmSa
0Iwl3OYmRyAGMVBgAr6A5kImoMJ9jGADQQgCBi5gln/cxkhp6Vu6JiIli0UAARRCQARoppbbLIl0
3uoZhHBqOJvVziIbImYEv0VRoTUkVURxCLJwt6Pl2cmgT3XAClM4xhGsghULmIADxImQyZV1BOjc
QBXaudJ3YAgBtGFoRq7T0PdYVV63CZJEvrM9s0hIQsiR6zv1dZxUCbAgX9rN7toV16RMtSJaS8zH
qKQYALACnfbw6Os8IE6zLqRoCHHANacgiFR+IAbzqwtuEsq1CNCDewfyTfe8t88P/8KwGNx7mff6
4h3Jgik6jQHL0eoouAxhJ2IFIeMh7CHOcUKvrJ+FEYvImdEzqDWVg4hfBOr5ysNsV19ZHJ1P/xKB
96UiFawQ4So4ygqWdq8f7+BeQfYFGnSRzbghaibAkBK8idJDon781r9sQo+YKQxGSlqTVlUoCc/O
EboIqIcHTgfSgThAuSEQhAVSuVK3sMtLB9IOzVzbSoZyz3uvTcUgfmG+Q0xBmyyUwAhi8I75FeO9
sDxorrDWSFnirWBMLbAEFdM5c8kEOWTDVTJBZrtRRUAM61uFLz67EMUiwBenQ10GJJGBArzAATAC
wQohgdIKwJCG+nzAhfIZmL42pP90IGTFCKeAvmuegYXXROcL4XeB+NKDeJnb18aORZECVmhwXLqb
McL0qNzBkSCvvBcRkTZVRN2ORpwEAY5wVI8rU5jLkvByAbz8Ai9PWSAeWOEUNlDadl4AefVwbT/U
HKi+km6LrCAf+jRJxjxvE5vanMIgYniBGz+Aa9AK0HOmlpOmkieaHdnZxcCENSbtyzksUlhHONjj
jcyTHoM44wTKRc5Pk/oF6B51qdOd7nEPBATqkwAiBLFWGG4vNN2Tr4vgjF7zedKanyxjCQ/BUfSt
sN5uLAbiCuTj4KhEissmGS/fNcfIRUQ78grTYdulpBIjj7Fw3V2EYaakekB5H2T/ODUAPKC6UEsC
3TCPOcxJfW7n7oiTq95wO1M7Ojg7AL1iGIEmMdpJE0qAzmJghSTGSc4ro3UAqDRzh2/WLtxJ56lX
zdeC9KmkY4EX1qGbXdXHDpPh7MQrYkFACfZxCALshjwyF3XMzy3zdb9AEqiC8gDOgAiUsvUCMLwA
etfrSaLjeeDnE0MqTrerRFlWhVOoggXaGd9ZBxftxultiMDCLEaZnSGgATBEEHCBFTrAwjInwNxV
z26az/wFHhiIL7gZ+SpUgRVyFkMJAp7na5bwxSMQAiscoKNEOV4gWj3EGQQhCFcXYzCMKaJRNDcf
LDFqtctaUqLkiJBDUu5KcHz6/ypg9HLVs/4F56973GHe4BXpXQIhCGP6PAnjNJ5xm+xlnQNESuVy
+uL/yAd5MiAI7NRn2/NAkFMShVMg0dcRj8Ixi0RZ2TcS7IEZYyIAsOIvIAYA2rQATYIAdcd65ldq
qlcAJUgAXsZ6XhZ7gQRjvFdSYiQGIKB0pxNhDxZdvjBhDjABE5ABGSBWAOAL63MGMiAD9YZb26NI
ArEmlCEAlzY4q4EoTWQkMRM20fYdq1JF4xI9BKJPCpEKZ3R6yDeCIlh3GaB6GYBuachu6NZ+AjED
91dSv4ZCYjADr+MAAEhlODhhPBhqo8ZlPpgBV6ZCnRAJMjB5bfVaMkFIwTQQxP8CLpgzJVGyG2ui
hG/DefERES+jicizY+xhDGiFcjYnCWVIAGloiqiIfjAngmsYc+52LDA2RofgUWDWdGCih8+BAHy4
ZevWZb5YAL8IZugUCfPQaix1Y0EzNmWzhKEnIMk2FBKSY7EjN28yLuMlNr/hUxxCG1qYKBLhCygk
iCvyAhTwAgtAjhlwjumIfmfYjmhYhi+gD21IfmFUh7XYaZ9lfCtyZRMGaqI2asAYkL/oixOAAIRY
CANYAcPWPWDDLaP3EjCSRQ2lhbJCkb+1V761IxIxHfkDSwJAUgNQAq/oAKpoiiVJASa5ABlQjueo
iuxYd694ZeT0XMtSZfy4gy//F5AA+Y+lVgCh1mU/6YMGOQBTYIhGaGZoFlnQSCOXcjwdkR91JTxM
EjPCURPRZ4kZ5BrG8w/iFzgIUH4siY4qaY4vsI5pmI6nWJIy52C4uCOe5gC82JN255MA6Yc72WUC
mQFCuHdDUIQbtlJYAiSDFIFBxGwR0ZDTg0MRJDCE8S4OyGM8oYSztz4eKBC+4JIUcIYuqZIoqYpj
aY5naZIuWZBt6Zb/x4c5uW7qppo9+Y9/KHej9osvkEISAANF2HwrJSJRI40QhydIsxuVM21PSGjJ
MV9bYUOcIionYijssXACAIbbJIYA4AAEUI6qd46Z2ZJoqJKmqI7XiW4jqIoq/xdIpqmDcTmXrfd6
sNmasellaaiThAgDhqhOMJQPgqRMGikuUhM2xRcsYbMioAJTQ+aNr9IlkrYkcuMoFgQA5zQA8aBy
L0eW6MadE5qGLamdoFmWFBpzGeCVN4k6Ecqacmd3Ilqi67mTPalCZzAEhmgBBagQ17KgjDRtwGEV
DsRA+5VQXRNFpLI29pURD1BSL8AivhCeY4mdZ1iOZomk1ZmKaHl+YoWTEaoP6kZ360ei6LmGJ/qe
fvgCw2iIpdVhCLIRerJwjhM040EyPzMQHFQ0xSNkXDEmC2RBVhWZE3FZh1ACYviRZNmZnTmhE8p6
KGmhMMeZ53d+EZp+V0pq8v84d+iJnifKngUAeYUwDzLgd0nJEIl0kS6CXyjheYCFFcdXNyQDWg/J
cFcSOA1UEE9nD9MlCReKliqpjmOZnYC6pOw4q+AZgi4Jj4pqpaSmpVlqopM6ABJQCJHgdzL0Rkgh
KZb0MFD5Hc4iMcwJNm+XaLYyMG4ihbWBQQURCOrjdpZZoYZKjt+5ANdpoWnppxLqkmp5qLv6qKSW
fl0Gc2tYr5Eqd9u0ojDQAWvVZ8hoGtl2Lk/0UF0hL4PWZNWolR2hJNFHQDTRmz1DD0+HdwIxAWF5
jtUpq2toq9+Zme+ooaCpsakXc/Bor2hYlmXYihzKhqL2ni+gPp2ArBuAiMX/8A5VyWTJ8TAtojxv
5oiqIo0pcSQBeiXS8kPtEjOWoncWCwAvF6uzKqtNqoosSajniJ0mqaSdGZ7hCZ7uaLItq4om2Ir1
ypqqqaLIaoSUVwzgcotOtC/GyZwGMR2goV8kYzx2gyrBCUyb+ls9NBDXYSG/oEIvsCIombFkiaRR
q7EruZ33erUi251P6o6aqZmq2I5qqKgsi6WtCJsym7ap9D44ezB3YhYlAiUZuC6AxKYHNku/A37R
VonO6BTo0nA0cln7UJkgCLlhmbErObKyKqGQW5ZbS47Gm7jqCprwGp6naLkm+bxkq4bphk6FAAOs
dlrvcGM7NB6dx2YHQTMQ/whpD2echnMimfIsNrohEzMSkHFZAzADhot+g0qyGouS2Jm4Iour1amh
Zpmu5pq/Gyuazitzm7uorXeQhshh7nUh4PUbSRiYiVVJAuI/uOI8sGtJ2NMhC8sqVjIQNWV9+OFf
DASdYjCOWEsBuqqr/xu1hwuaftqdqmedGfqnyjuontmra/i8XsuOAizApRZvhpisQZBdjPEPAtBz
pnMB+9dX3NNKLBGR1rcq2pOFoKcSzrEcYLOMN5QTjGQ74TYA9mC4h7uxC5CdVcu7fRq83FmOFbq/
ZMmxrLeO6ji55qeZqah+6TeCxTqzYMphbIFrc7ZR7rVTAoAgFdQpPKs2FP/YVHORursBGeE7NwPh
Aiq0CgNxxuZov/JbneVKv8DrwhubmZkpCaJMtci7nexYte66w5hbli/pyj9srPJ5qdj1AEDHSb5m
rABrFl1nmK+rLKhrsOf7bLVSND6zn1JEV2syHkE6AKuwHGbcpOmYnetIAFcrx/KLvBrrOio2bGw0
bIPgAqyjhlAbuerKnZVLAPAKtqtIqfOACIFgPkLHSXKIZwMgBvHzDjX0s9JyMt8HUH4rPUglU3Xi
LxbCQz2xYCOwIrA6xih8uKW0krqKwusYln2aAyoWBCRACZQwCRzN0SRAAkM8CJmZoYB6pM1bob16
uT5sksW6DyEQAp1wBvv/QM/1/Gu/FkoYgFoeFmnxop8YtICQtBQJ5LpYfEN2+hz0oEIlcMkcm8Lp
iJ3XPNXZTAEUMGwd/dGUoNE7wNFdvdEkgAEkLceteKHmTKuwTIbgSQD+YA8NitOfxFUlkHgjEG8x
VDoBcI39mUWPAyKFUr5EZi3OynBNlSqQsThLvU2XfLUPncLajL9TTQCDMAhB4NEfHdIkkAAkAAgk
wAkhTQlg/QFjfcO4aqiNq7I8nI7+sAr2MAIDd0a5zE34l3SScAHdQRtTsD5DvNNssSHAlInPqkdG
g1h38roWkihqcSQNErHhcUZOXcZyjMmzaqu2ip2DYAEdvdGgDQgJ0N0JmSAC4C0CCQAInA3aW/0B
Vv2kbLzOY7m/BAACYrAKeZpRvIdGIzAGC+ACeOgLIRxh9XBGHLZSMdAdMBJpLRGqwVK3JhK+xrA/
FBS+E6VBK4I99KBNywGr5hjZFC3VkI2dOaAKFmDZoO3dJF7i3v3ZIf0BrGDRwFuu5GgIrf3aZzB/
2HRGJUCLxNeWCLDUypdSok1j9JN2E6vF3v/XPGHSIxDbONy3bJLxAJx0yRv+0JmcyWTs0OmYA0Hw
0V1t4lxe4uRt3kHgAuu9jmRpzfGdQndmrLsH12jEVfY4k6B1iw8hCepDWuvkfDZEJqu7hPlDnFv8
RMoENOTZsxJuNObLEWhkO6JcxrPKmdNtzaCMwpJQ2R1tAdzd5Zju3YAA2iLtAo6Ofgvg1vTdQma0
STKmeGCWWKO6EFDyD5IAeRugrH0mNuKLtw8YMdZWIYycI7/9n9QI4UlWAmTEIrA63dBdSlHepCwc
BBxACV3NCeKd6dK+6ZidCujn1ulj01u1QvGGdJKQPXDO6vko7gGgdxlWWioVPzoaRwfknw7/gyoK
0kj4WWgYoxrsAU0N+HRTZgykjOyNTtEozMkS/dCD4NGTUAGXjung3QDR3uXUTgkfIAn2kMv2DHkE
p3Qqx5a3yCLkwVAevOaWSm8FCBdK0nAzqjlAkxPY1mTdtSWooTWuFYqntuFRbcYRXcbWbMYfQAnu
wNHQbuIi0AAQYAAGcAAGAAFGDwENwPAm/vBBkObXhEISsF607QCrrodPIwD1cI1ACkqGiFK7TUMO
OWCJVJg8gz0YKVwmoZTZoXenx+8oXEqMLvcDv+HnyAqU0OyUwAkmvvRD//d/f/REf/QN0PSYXQUX
ZUJehXs1aFelKSC7ETojh5EZAYaHEAIs/zqA7aQWnTEmt8TcQkYhGxc6zVNBhjYlxtWAjqh3OtLQ
01zlNz/NKpkKId7RgNDw3d0Agh/4u3/0BzD0v6/0JO7ZHK0OqzAGd8jfNziqUIIpnbZYlF/BetcC
1au2O/0dK5+fnfhP4ZsfiJkXPOoQqaLgTbRUAuH2AsFldC/3Ad/Y010FPW8BmU3iIhD4Q9/793//
B3AA/2AMAPFP4IF+CUgcDEIPAQABDQE8hCgA4kSJABAgqGfR18YAHTsioNcxpEeIIwYMQAcjkgwL
Hy486BghQL98EwF0hGlTZD+LEAOMXOjTY4CHEn/m61jxZsiQE0V2hGgMxL4BDh5KWrCAQv/WBRkW
ENDaNetWCqkoTaJEKcFathAMuH17wC0EuW/tHvgHwJixf8bw/oNgkASlGEojMjwssd5CjIwv1uP4
U7JIBJKD+jopIWWkDYIwYHgQoR/TABUl9iMJIC+AfCOLPuyYj6fToRGRSp4oMwBS2gFk9gTAasA+
q8awZvW6NazXsV8pWJgEnRPbtXDputUAwW0D7XEP8PX7na/Af/0ODp79miLEixbbX4S/0ddIjyPp
Q5Q0XAKMIZw9v4wpNYhkoskm1HyzibR/grrJN6gqGs0jpZ6ixxiLBBiKKMUoOMkBCyWhQDmtCBCR
AhJJXGAQDijhgJMGqJvLLggaaECEtUT/wJFGvPwyYMe+/PrngAZI2IESQGw6rLHFLFrssQsxioyp
yn6qrKmHhKAqBHQiWSkIDGKASbLfKpryJ/aWggox1g7UqTahRCOqqKPShO0oeiZyYThJGHKguRLF
Uo4AViiBzkjquJOxRuoWTeAAR93acS/yCEqAkoP6YQyAJpt0rMmeHrtIvsmeGhWiQwY4pIVCuNzA
ywsIvO3OiJ5Sk7WYdLoPSaMibDNNiTA80LQGZxKuqrz6bC4H5ZRLjoIg3GGRExtvPMAuGhldFAIB
AmvA0b3EA/IAg9JKh8n3znWssfeYjIzKWBFoLU4EJJDgDHT626CKD1x654G8guqITb2G/0WNwZl2
k7VOAR+i57aHggpJtAQldAq1CPLbZ08AkF22Oa7GsqBQ6kSI8UVsF+2noLUaEAi8vsgTAZCDKMEU
PnWX3NQ9c0PlyL5RP3qoHgkG6GRLGWQI4oMviwkgo4rmjPMhmVx7euqoG9QtIgyPMkw2oCFCysqK
dOsnFaokyWuCsJQdMYewyKoCLQ6yNeAtk09mi+W7IQjy273Ge3EwEtKxGV3DPVWyXYUopHOGk0JY
VQZBvMSg3wcsHJDWnmJDrbefjAHYTZ9CSo9h3F6jbzXYGg4gz31SeciBjrki6+2Q0QIkb2sTmBbv
BPr5B0byXgZv25gtpYSeTUHVFL7m3f97T1T6RsoHpKhNGkDVSASpooLPALw6QzVJSxgApngbXWDE
dCu/QaQMczBqo2aiJ5WTWIndz7DW1krF6KRlS48MUKMX9e5kcjlUkH4kHryIa1wkwEDhJMgpJdkM
Mr7oCAbrMxTGSGAfEijEEGSQryBcIAb9wtRr+mE1p3itJhkZFj1KFxsrPWwyRVnI1Eq3tYVN5gJU
mUH+avc2jwVBZLrTzrVeREADrkwAd0sA3wbiMgsFLwGAsBQJ5OMLC2ZqSe8RAM/m45EIWO+GAMAM
0TYzOaVdoBgwUZ35YnM18tEma6sR32t2YybPqeeMiNkjPRxwv/zRTn9dYQV0LDAdatX/rYBKXCLv
DlUPtuSuWwNpmaSMMS0iUeICW+SiBEE1ysVEaSiLC0BQJvC4QhRCckm7wAXeQRMY1sk1q/EancrU
MNrQZygNCYAxMhTGBWVImMPyCEaE6QCqiKGQHQPL/lgRnUlMJ0fbodESs6nNBJiMb4sSQT/+MsXv
/MNkyPsAKDdyMwvqDAGi+ghp4gUREJykBUOAwQhh+Y6O1EOYySRKQD2SEQQUszZEqQcHgynQHooO
meFzKDMH4MyNzW6IWwkCB9BCwEbZbZsfVWI3f+dA4SmQeHsJzBWR9051hlKUy+uZu0j1sBJQpQX5
lFwFXOIvhdGpp726GjLh51CPdE4o/webEFGHNoKH+OJjW3Hb/p4THUmKoAF1mxFItbrEby7qkgos
ZwM5OQkSOECdLHUpp6AHz1O6iR4eBOFKZFAFypEkjz0NqkORCVT5xU9DD1nh6WwpG/bQ4ySreObH
pMqKFXHAqjSaC0izutWRYkuK5AlPkKaFvHRsxAMtdSk70RhTKd0QAcI5RAj680rvXSBNNAymUxpW
OgCEKQIJilccA/Yghf0GItSLk1HY95p5DYCpaFTs/sYStxaJ9KoehWx0ZzRZGokAL1BcCyDoMhDt
OKpavJMZJYLgi8+CVj4TlI8vSRUUMdgzcvlq42tJV5qjNgUBmBPdQnbbpqz9lqikMf9YwGryW6oc
oqkz4AqCDbkAC2g0Bo/tVlaTON3oVhiy5jxZA/oxoyg2UFGVSgt5RVzelkoQngrRjUhoepKUzEMQ
bJQlfWOYVwEJdybqiZBCPBc+Fv5rjzcGpGTuRKYpDKAETV2wiLTiDujkCFEDHOBVpTzA6VKXO+bE
Lras+48enZNI9BixZ83ri8VcEIPTM+PDhiaBFnCJe97DANPwOMdawYSXSf1cCzuiWw5iiIdQQQAw
D6op8QVUaAOQAJIVq+CsDGpF2+zyjOz2Fu1ImkZUvnBI8XZJR9poMBa4gFk/W14Sj9kB9VBIvOoT
FPsNYAohfKXS+tU0YZapaTe5yT//JNSQPwf0Jv+Eiq+BqhP1/XTH2HvYAhDM6GX9QqOUgLQjq9wd
RFGbwizLqu/WEiS48I4TghPzqMMMynciwKy+iABpSmUMIZwKcqxyFUxSPNSG1tund2XIwWjsU2Ri
Dq+HGFrQ/NEcRmclo3PLJl24UzK7YLXSltZRP6wqSbwFCatsIcEkMOCAUYs63OY1Kz3SjWJ4pfIh
HkQJPvWJgVfNRDfwy2XFetiwGj6UIprLnMSiEjGT+0Q0SBHCSXzxkARzxR+pyEqDJ7FNuEjZOpTu
DpSpPF0hZXNRuVtZtXYHYkqYleNhJrWIt+h1kYs83ZJZzdAGAAOVSK6NFhuJYdQ9/5GR6LxOqEmh
Lfkdr3zQu+c9VcouA7AKqigEAcpOsIhSwYFHc6dblJYRVusmecg7/jpZRll3FL6WwezgAh7oOHnF
HXb5OMAB9AhN2Ucep0HuYwTocCXSBgGm24jE37ZaWNi+Zoy5C8VrE0HAgdKzENJAJCO+QY2wJAO8
9laF6IhnNIIpwHhoO97hDYdUj2I0l+1Mtx/b1HJBsM95QoXaA19H/+jF7AvTn/4BqU93uh+CWtWq
pDMsh0k9zv6ghYxmnv5tKKS4LaFwDT1iCj9ymF4KKhcKgOazCgQouGXLisWbhG6StMiLCwGqm2qp
lu2zm8uLpEURkiiSEbZICww4v/8U/CxR8zhxYz/3Cw0HiIAZ1LHiyh4ueaXKyQnOaRM2CbSbiJcB
NIriwzV88wj0SZ/SwBxgo5OtGQn7IY6HkMCCOzoO6IBuWjjIyz4OFCCt0zpribLvu5ZseaS6MADw
ooQd2LgUZD/Q+7oVDLP2e785lMEHYIyTWLvV6p44Yx+i+qObOBCIsrcMoaOZICwCbA3aKLYGPAlJ
kAjog8QZUBEOwARJowsN2EAN5MJNlJHImpGqgyLuAAQbeToTbAny4rhUHLE3ZD9UfAAHmMP3g4AH
kJVBUiOVYCOWm6UBU5gViorgCxgGMZ94WUI5aiiBOb54SRh4mS+LsBCRSMSeMAb/KIQdAMiK6EM8
/+kmqTNDDuRAfHCULtS+63O8DWO6lFqZuXAgESiSIEjB9FPF82vDFzS9dygGy5lDhsAYyHGlVhmE
ynmj8tkgYkPC4zsYTSmK1kDCOumv1VmYA6k5IyyWPYHAa0Q8xFMFDrCAhYOLTPxG7zIAcOTERIky
joQAW8Cuq5oLExSvFzy/VHzH0fM6SXiAl6jJB3ijB3gI7FEVGCCh73kAwgodhAGOKak51ogYA6Ef
CxnKezNEogAYvtOj29BJNcmPAcAfANgKCUQ8f/iADoA2KsvAj/QukTwAcMQHceQ+TFuiJlqLhtss
dyir9otJeIRDSTC9l7BJy3mI/1Nhs8hpiS+xnCHTu6vRNaL0t1wZnYYqQP1iIUCyD9laxKuEnYpU
sCnMKGjryEw0y7P0rs8MR63zxI/Cmw4coLVIiyBoP7qsy5dcQQfAS9AAjVjiqQc4iU4wg/6AMTdq
SGRqH9Pyif+DmAT0PZ/ypYq5DdM4QsOUKIqigCnsyszMwi0ETdA0S5EUoJKhrpNJFNSEltVczdZE
RdPDS9qczXewCPuRgF4oBJXong+IgZeIgJx4kwLBnHq4jQH8LYvpFcK8Oyt5RsnoOwCMSPr5q5uw
RfypSBCIRAZbEcgjS7SsTkcxS03sPtKspLbYOk4glPabAPCsS1XEy1R4h1iKpf8SfYhVOIkyiAQR
mhxdfAA2eZpfkrkD3Ss1UbWgcoqpuT3UOErhE8ZADACJGgOik0B/mIGBm4HMjBFxBM18cBQEmFDP
nDxr07RFkbxz+s4PBc/wNL13dIBUcIDKIVET7cuTYDv/CIJ/ZBNjCMRaahAfvLvWSMyiwjOfsrWi
5BwGqYyGXAikOJA0ciYEoAAGZVAJBIHMbLhqkVDQDI8DkFIKDc3shLgxZBR1ZEkL8FAH4FIQdU3Y
dAAXuACWY7mX0JTM2IyfjIEyGpjdQA3M0S+aK0TciMoDFIpi0zUZkrH5AVC8orvJSCPE0soFOFRi
VTZ/YNLu6pEn9YvweFTr1ED/a7GyS7ULGxEBSpBL0+tUbe3SVIRNMR0EWYolDLiTq5yCthMEC2it
PSO+PzzO0SFONNkNO+K3HzOQrFGKx/S9kPCAkxADiZiBZUPSY50BVQDLyROgznQUKM0Hv2hYSK3O
7PxAq8OWcWTJCuDUjN3WbYXJEWW5cHWBd8iI5kMEdJgHyamC78mHWuKgiZCNAsyLgGmYXwHEefpB
fLMeGfKjhanZ2JIIYRqJxViqh3jOQzXUrMhISshAhYXSZvWW77BOCq1SbAI/LIUUE5wE1fxQLt3a
bk3FVHABSXgHDCBRlrOIItuHNtseuoovf4sf1cGQkFhIWZ0hXZWxBinAhzjM/2jMnJkdH8mAU9YJ
iWCVQmVL0mVL0kEAS7jwRpF0VqgNDyk1BigFTYdzvOqq2JVci+jQWm7NWI39XG2VhFT4jHcIV51M
I80QIaTxEjC5NdMBmhkVLN902T/knLzK2160idpTyn4qrhGQiEI9XIIFgUnsSM/8zIeV3IZ12s8E
Rw28UIrNmxi5Eej4gK3F3s/lWNNLBUmQhAsIVwwYhDuxxVfLp1ZpLfp8CFXTrTCBSr04n6tBjXma
UV8Kk4mAiXgJisrIMeBAGAQBDgcYWq1cNkNdtlTogEmAlOp02mZt4AN42M8MyUS5XEZRybdgi+jY
uK7lWu0FXe91AbIVX5EFgP/me7cuCVd+konWmKH9gojD7Jz7/F9h3C0a9kOkKs4D1TfDDAAJOIQj
00oQmIFDRTAQAIHF44AnM0vKdVi/eWBJnVRqq1rdsQu2gI5BmIAsBl0O9lzY9N4RFt+FOJXsiZx0
ZTm489He4CV6BY44zSvd4DOSwKMIKUTSkS0HAb63QhWiFWJiHV4h7gBKjFrIZSCL+I5Indyy/MIk
KkmKq44SVCkOGAROzeLs5WKNlQQXIN1BIF0MsIgzQLQhKISTbRUTAtT48V9XFUi9IkIYUkyG9Cnd
QEIBqD39fCgGEQB6KLJEE4Dn9GMkPVx7CGQS2ECFnVwH/ptmjdTKFc2StNT/rNuOteAE6HCBSqZk
S95iL5YE8RVf1L1NGFiVNwMT5UkxXkSTpnBbW30aAeSv0ggwxgQywCJC/YqXHdJjIC7aIh5iBBsB
GWiR5/Wuhm3avbgvcHlcv8BOy52sJspSaWYySnaADNBY7OXiCQARFxiEjB6EVFql7GE7FwuCEoIJ
ozQT2d2NWqoM2TBnYKw53qOYo+ociPlf4AAuPdKcpymyAWCIQvXjPgYBfygBROiACiBL72rgZGYg
h3XeZr7cZ4ZkLGKRSpZqibZmLe7a0dVkbl6IevJoEYKvWcPPVx7IifBR+jLph4GNl6PX8HllZQyf
wIKoEgg4AEgFIT5cYK6n/0AI5GX9TKe9r2T+G6hlZoXOJgPijg50aAsgAUmQaoqGaKvmVArIgW3W
aIvAQ5XLwWL4DRpq4d/ricPkt6kZ0PqyEMOwIZqokB3lo9/yGhp2X2NANgI24GAmGsbDhA2kXIh1
YtAhaL+QXEmFXgPQAKu7mwsuIA6V5MZWbqm+ZosGW40ehI05iX1oz+1Jmi95v5VFjH+SCYmAmECk
6Z8wqnwzRJ5oyqvZmphWjb2aEF7ZMWMIhJNYiLr+5YCdgXhAtA7oABKYUmTWpAfO7bMk7GwLoGpF
TY2q5uV+bOb+0BDB6Iy+gOA4CRt4rzU90ZSZmNxzKBdaZVsl72JzwqA6kLWqzJw9sw19K+GT0ElJ
MGIhdvF7IIOTEAQO2IIeEcnf9m/AFmxmbjriTkfNrZRJEISIZuwMmOrGnugJUJZU0Gh6EAAV7Wru
cRUwkT+0ziW5O6MhnN1SeROfwpCwsYkU8wmsEXHWIQoHpGsXr+8SOJUqCOQJldyC1gu/gVioBei0
rDQps9TH47AE4AQmswBJyAAjL/LlRnKLlmyNXoia0ozICQLvscd0M2c5yl1XvbdYuRAg9L87/8Xd
AvHuGwXA97WIYRKOjAEAFu9pFx/jGNDv20bepzXovgAAQo7YyWvqD4u6c2KRIMiAQid0Q29sZWEF
RfcFetEMtkvXf3yj+UyY+VlINPEt05Ehc54pAqSTjIhMusstBfxBh+ycYnEAAahrIx5iYuXqAQgA
6kveKIXagnZiCF7qqW1qthABh5uWSWC8QRj0fZ8AIzdyizZ02aEAjGYFT24183UxOIuAd8hdSk+h
inBfhFKYpoCQbJ+fPZoIYepNQOQ3ub1bAKAJkqDGU3dxF/cH/DYuACABxuNrWPebWf+Wh1Xq0CwZ
0sx1aW4wDtj3Ivf3Qmfs5ZZsSRwEFwAAnv+MHLrCv/er8l+pvTiO5TlpoWlXQEJU7a9BE/S5ePVe
X7PBylPf5xafATbvegzQbwhQWBz37eaFd5BMS0qb97eci2nhBI2qAove+UHvd3/v90r++QlAugeP
cKpACRhwsVZRGn8x6bvFWYf6M+Db4bVmDwErHdYZjd6IdkLDgJOYAQFwgJLf5zGeANawQkpYYu9C
e8iNYODWOj3nqOfSDrZgPEmWhALY90EX9H73+Z//ebcZdlbgolOZArXtDMpBfF6NZ6xBjdUQAGFC
bVwpGDbesVk5I/2KkJpI/AS5AH/1enInd1CQ74cIgmFG3oNu9x2vXHKcLAusYtTE90AvgAL/eIFe
p33b5/fb7/sJCJEcyOhTP4lzBYhIMgQF+YDhwoN/ABb2yxeAXoCFCAAEqPhw4UIBFSECQCBgYQCH
ETFShBhgIsaNFVFSVEkygkV6JFX2Y1kvn4MBA4QIcABiBoigQQ8NkDCxHis2HSocaHoAnzGnCA7k
ixq1qlN8Tw0cMADBQAMIDcY2SNDA64GyCRJQ4sAhSIEXcQsUyJBBkt27E/Jm2CvpL4UcCwalEiBG
Z4hCAqtsMBjjgQCFJTfOfFiRJACIDTGbfEDypkUBH0FaHPmxH8yQo1umzthSJEkEAR4M2CcGgIMx
P3eD0Dlloa8FHTqwweS0KdYDUZEfz3fc/wB0CNLJkvXqdW0CTh04uHMh93vcDHXx2sU7wXzfDIFz
DHoHoMS+AS2GRBJkIQgGDA8eGEuZrx89+bhmUT4yAdBfTAGM9lEA/VxWGUeVPfAgafQ4CMBolq2U
EoAP9bfQPyHpNEJPvAVlz4gLObBAFcNZ8NRxylElo1UxdqUVdGeFNZYIDRzwlVpsuUWJC3OB94J4
4pHHl18TLEABK6w4UI8ERaETSSQbbIDfBY9RBJJJI1V42WohUQhSayxZ6JBoKZX20psYpQZRmSEB
+NlDKea2G1Bk6MTKQpIskIoMw/k4I3PLOYdoUzhGNx11PmoAFnbauRUDBi8cOZckdY13V/956QVG
wSD0TBDfFOjAMFAQXL7Tz4esXeRmSAYuVM9G+XyUYUURuNYSnZjRehlKslm00IdxTmRMaREFcMg+
JfQElFAgELWPJIEusEChS2llo1PLZdUVudGBBdZYX0GHXQKTuMVBMRd0Ct5cdIVXV6jlCZYDK8ZQ
oFMLhcAwjyBVfPCYShUJwFJpuzIYJ4bNLkyaRQgkCzGaZwLgIEf1YORgaxgF6GBECFQ5Am5jAEWt
TgNMhIA/27IiyHAJfLuoMYuCu1VX04lVnVcQiFDpux/MNm8BSGvK6Xj4kkfAAuwBMALAkQwxUAX6
TRhig2IuNOGxH6fmNckPPtx1ZWFTPCv/RgVuBqfGGkZkTAkDHFKPL9QKpVMJCOC97bYtbvfOt+Au
qtW31lmnY1iLYwfIux0EEUAESNsrV1yYY87XXVETcAECdg8AAwwCEaQfTAjAFOCvFV2YNrEVOlhn
QxHxGnJKI4M0JmYaety2S/8ccsYhKf+k8hg6rbLQBDMAnoogHHRgAVcwMgcudF0FveNZ0Q29FiCU
bMeBIIIE4MDS6WdOF3iddpoX1DnQk9MAnSiWpcEXvKpQTL0XSKGxQsagsWFEIxCJ0Nq8JoA5caZW
ElkIRBwSmw6R6RASKAHe9AYCFA3gNgAQFOD8kYrheMspOmtUo7iCD3U1bizZEwu7thC5/0h8gB4X
+A4Oj0Qve7kvagvwBSsANoTSyaBVCAlAPTQCNgyJjGSr2RjGSuMr/zRIQEx03Zk0UhErugmBB7IM
PWL1mgdRrXi+0I1QyBAfQAGAAs6jwLYosAEScuKEhXMKV6Bjrh1pT2jscpf0OCCDIVwAA95R3wIy
QK8c1qsABMgBBRCwCoARkSAfuABMEKQ2/lEOiXAyCRMz00nbMeSAXutV3CykIJbA5G27EslJACCZ
h5CsI1Qzii+OBxSiDMABC9mW84CZAxJyAB8qHNeNbqRH6aiLK2NhFyfexQGrReICFSjGeZL2AkmI
AQRLmxfmjISkbeWAbjqBAX1ksKVBxP8gdbjq5BP/FwAxbpFCAoClrVpyrN81S58VMYZsRFOxevit
Iv8gKK4OyiyC/lM2LbklAM4YFN2AojYeyxswAbeAXyhlOxAoV1PyqL2eiWWZBuhRAr4Hue1sZ4gw
CAIM3uELB1zABYMQQzziQQHx1EtT7StA1Cbgi9pMIRv02YAFDPIOVf4DAf8QAEMrQtCFNQuJBY0q
VGVTD2ZV7CQraepKTqJFtfnzlFHEmBZv6Yt6gEA3M0DRIfqGG+cFU6NVEIRSOIAJAyAumeYK2qPI
Ypa1cGIS45sm6egTCQzgih7FwMAMxhAPMfjUSJZFEtQcEMQBTEFgWSpIl/YjwWF5zVj/cSOrP3uH
2n5+7KxkZW1GHlJGBCBgoiCIh048CEe6LiCYUILEcNjAgXfoMY987eNZfkYd7JBAmh2wmgxkQMQH
EJQeD2BFW8dAhgVsSocvuEcOEEA1+QhMBlXgEkIc1A/YmXW17j0tTJ7YEFCmpJVmrV1lGrLe0SCg
IeNda1s3qMYBUGAhbsxoRkVIs+FwgBIQcBR0JiUdsIhFuWppizSDYIGByCASq7qARRywsjFINn06
DA8BCnwto2IpqfppZwRgArspkga/GGGWfjGTGhozJDTsHRAqkQWA1bENWEXm2gji4wsE2AONJSCK
ByK6ABD0tsp1XQArBLedLZDAmNrz/4qOLNyAoUWTwdOrwAeCUAX8CcRoDyExGiVL2W9e9gULcEHo
rJRO0KbXJKzsGin16cUE9Q6UH+nPfxQGoTOZsr2XSVZquNiRhwRCJ74AwBiaDIK6DSDKGK0yqDXK
CguQcDuUwERYJsxM7o0ZEO4a33YGcd4qyOAX542uBaibinjAGSiSnUFPxZmBBUyAfqlaVREP9o79
dDJtEVgvaTGEEov4qj8TiSC0c6doNyW6IwvBJ0Ah+D/P0CpCHwlRBP4LgCZnWidGAUDzrJzRK1Og
RR1l8Km5p9zwuQXWbAgCK14ApSpI4gWpCEJ0BTGIB+SU15HNbjwUedm5EMABQqhNwP9WtaWDPCDG
Po6YhiqzOpKEiL68itDvImggXh1LNGNVtLPeJBrTHmuWAfgFUXxJ4ia7O1BUpjJvgx7HX3SLOCzl
gAUowQlKMD1ywmVpFVJhZ/UISj2MUWcQZkEGMvC6rb4Wgj0qe6RhI4CXpMPSxjH5gLIxqKwTiblF
FGLzy3hMAFy1iLX96XJhpRZ2qj3tsRBwmF4CILuT7OBCZsBbKof6SVWG0gYiUWqjE5Py0hvOBn4h
CQKk2M6aitpdzQsJUGyd6ySeqGR3WmckDbU25d3AeTEQgwtIZm1/V9CPh5Vtf/IYtgfSDO5ptfuN
JfqJcsPQZrPVVntwOhUAqEeVgS7/b95qdAa0lkFeSYhXlnJfnawggOe5SwHwU0ASFqjCDWQQiDOQ
3vSnjyyvcbi+pHlAJ70Y4kCSeskHOHXauMtY8IHJ/8BNgeTXmWCR1+DKAN4KAPwPj4mSFw2ZzCUf
ppEYL12aB/yEPziP9Mkbgj3JDNjagl0eCbFB+WQeHHGXCnre+A1bq2xACJzBGahD6fEa8rSVEPiD
+nzHsNVGYixGQRzEO7QJyM3GjUHRawGatxlZyQCgWS3gsGBG2WDE220RE72dKo1EKsSH893WGFSJ
yyCAT/SW9Ald4wGOG0XJXTFG+VRBFfxClKgHC6pgBpAfd1WAKsCgLMhg++XU6U1U/zwsgLAtgD3w
0nwQjCXFwDsUg/HV0gNVxITExkNAYWY4BOt0UQFmSJhQoQFRDmcM4O804AEZHywtxCD8SeHFAwcV
TxsBRW/NwAZuIODw1oGd4bakAiuA4Php1E4l0pNAzfhRgMAFwSCEQAj0Qi/w4db5YYDJmU8RgBis
wvC42/0IQgUQY5eEUZkIUAL9mDEwCMlAG4NsYrSRRO2ISRVqDPAV0GQQywXoBAisWzxM0gUZ2M/B
otCZ4RvxokbFkePB0bA5XiIB5Pi9AAEQRCCEgCwgowzWIIk9nJz5wyqAoejUz5WYF5pxXAT8ztkE
YCVumyxBIqNpCMPUSkTY3BKVW/8sxdYkqlbq1EnYOEB83MYMrMKA3UYurQwZThlPBpNPZlQK+qNA
wpGdxdGwDVsw+uL4bQAkGOMx9kIusN8ydt3xSJYEUGTL7EPAmA4xyt4DSFo7siOgOVqgmcm2acQU
khYCmuMoFdAokRvFzA7D2FBupeK1FIaI/cSU4SNdyeJP9iMaCmVAOl5ApuDUreACFAwkNOVCJmMu
1GDX6YZkjVdtVKZ8ENGWHAzYAJ9MfIh+HeBsgCbahJISUqFlPCAqtdfrdCOtjNbD0OUAoExNtowv
pcI9biA+luH0yVtQwlFvLgDUxFGKISViUoAF3MBiToFCJmND0gIZ9Fp2kQF88JL/3UjAwKhT7H2l
gpikrojMJOaT71EEJUpggKzGy4ViWcGNjP0Ox7yN7HjkQzwAUaDMbbXMRFBAUOzlBpZhLO7mLAKm
b/4jHKWYPw6b540aYyzmMS6kMi7j+5EYZe7DGXTCPGAJrn3AB6xdU1EQtFmMRaymP3mG3UFQr2RE
Og7fJHoNEy5hwsDNrHASbJSbThTPbMZmRyjeT/AlT+rmX87AbwqkUO4iQPrikxjoAmgYcjblgiZj
H9qgUEhWCUyBcpLOdcrAfRjEEhFafU0iTNqTkRXarHgERXAMPZllKAUI3uUOJYJRoMlGBNCDbwDA
DPjJACwPAqyMP2jgyuAoPvol/6j9ZWDCESQBzmA+SVLa2cHd1WImJDIyp0N6HYnFQwiEAToUQjq1
YdZgkoLcU4oCWRL+3z+gaaBxakiQBKmCJn31WIAYSDqGRCgSSD5xDT1UiQTIKS8Bik8ExZ7+3AL4
KQfOWz+mQswMpT+mYC8GY+c9ySBYwPlBQgsYI3NKJddRJfypAzqYgaoMBOwFYQxECAXlkymB54f2
TodI4QGZK+AdIDmCiWXMxP+I46RVBFHUqiQ03wfp6m7E4p7uqH9SH7H+a1ACZ4ASAAiMQBUcZxVA
QkLKAoOegUP+IYm1ADpcJFIFQdYchMIE0D+1ZkTwU2mwhGygaSiJktmABCyJEf+tyNgDfWaZQgR6
fuhIPAvxyGltHIIv6c3K5Ki+Sl8HnuGVFasPDSkFDOkCrMIU6IQ6qBlyOiUyRmWTPqRkxsPErsrB
GgRC5MPanUl/rSoDpieygIw9rWW4ARqrem25HYh3QsSyCKCKhiaF3FIA/ItOeAyfCgUs5ijQ3WNv
+aq/9pZgBGo/Dps9rEJ8tMwhQIIFKCYkTEFj8qFz2qDKtFU8qAPpsIpXrt1XRqIBuqRptCrZOKDI
gWZKPp8olmwDhs1H9NdGfIjnSgREzUB8oEwuVcvduuJuvCK/Ut9f/qaxAukkFW7LuJvSVkE7QGvD
PuyTkkELUC2XdNxY6lhLuqj/17zrSLSutnniFWGM6sbXTJgEKZobQ5QihgweAsjtbeRqzvKJnuYm
7vIosALotuTptegE8ELLBVWBOySokjKktLrfw8XDCFRoFVTAY4BNjM2OtAnaA7WjfIWcJv4PSmiE
POVeFLqGfuXTxkTQy5JjPRyGUQxegUmCBuHsfuqn4vkp4/XtoGhUDthDNEoA8AYvtOyDMU4ss95A
wjZlLxzvtL6f5P5CfWCpQa0r247sFtHDE4kq2Ywrh1CG8LVXsGibpNGcqTqEIwLA4PnCYeyDAwgA
fuKr+vIJbgKdvv4psA5rTcYDdQZvfOzDPihnwLiUlSYoIihno/Yv5PoaGUBC/xHJXgCAFUTQ2Gvu
3j2p0q6koxf9zyV6TK6U5Tn6D4ialoHM0siZo6jeCvlyGoBFLhjjK55yoOLtre72Iwiswgg8mQxX
5iF0Qgi0wDzAgGKUDpbUhzuomZI+ZYMyI/KMwQggAjHGwGWIr5ygFsesZCnBRspFkUmIa5g0DEoE
8oVMWxQ9W5G9UwBslgeAIQLkZCeH8X5+ct72ZJWNgdFyWvC2jAR0Qi+0wPIKDBHNQ3TF8w3n8HIy
Zx/CWYCRwS+k3QMg8cRAc/W2xISI6xVTFVmF7KN9TKKxhECfSaKVLJF1J8VcYu5cl05IQuwaT4CF
sfr2ZDj3JSyOQVyBYeG2Mf9RsfPZyXKFqtMJlo99KOriPqXTOmTOjoEQQIIgXNKrwI64JqEDuaUD
GQM//ccUPbNl1J7ZTobKTvTuHZ80N8hmHd5tSALtVgtvUAs492SebhqtYmV1pvPyVuosw/M8wPMG
lM/5qZmazbOCLmcu5zGE9vFjrMaqliqyVNFKXIwqiVExq1YECjNrkmjLiRvJlCQlBtAvxAcY3iyk
gjFWg8A33+5u2AMZ0Oo5z+sUnME8BIw7lw48C0LCCcK2XiNpt4qG0fNTMqdz+i8gBkJj6IdCgKNl
7MpkgGg95ZNsdBtJgI2YfEQgG7OsmIZ4tmsXkcmY7F6INMRmtYwvCIAGHY//3VY1ZFOLP0jnjF63
3UgoHKuKh3U3wWiraKN1q2AoBnzAIJQ3CQTBDRRMCCzsGcRg+z3n6elGPNw0aHlSScTomPSeS3xI
yW1IsuBXSRoUBYsSfo0G2PxHZRz2Q0RAYlPnNttDZD1cN6cvUNhDPNTNPqwx/UqAcs6DWEdChYo4
PLO0aB/sABfEeecHi+eHhlnAYiJCajekg3KyZKnDa/NHjYGvWTahPhUgadqJXwffaaRqjRm3kfV0
kdHShoCIRZwiOovhRuvqDZqIPVA2p3F4fHRCJyDC8qKTZ8dzwp31lhTEeJM3x2HKBYQWBrQKDu8v
Qz5mjTfjHg8wiFFbiabt/5KbUtqg3EIQEEmI6sQIS2nAJUiMbsaE0Y2BbfVCeUbb5kT5WidLFhlY
UEXSb22wcisLzP0IhJiT+X2Y9jUaxEEUkppfANY6xAPEQHorrnI27NNGLokJQewdUaEpuJAlWj6g
J297zdhUL1qGDSOXZgWj7ZtIBs0Vi9cKgAsE7/Lgp1tZteRKJ4cb7oSi9BDEsqdH1waYuGmbuYof
xOyt+SK+A4iRTD+/wwcgrIzPOPs9Lj5X6+kgjGk6ce44SJmGTToCuckG8oKL5lJPhIPg+sfojvRm
xDuKjiQIgNdFeltZt2WycVHYgMSeHTxjiVm34fmlNYau+IrP3rJ1XLk77/+wr10MnHZb8298O2l2
jUEg5DRCxApaythEvOaZzBeSU5AjJyF9PXW2fYQ8MXRp9MfJUcg7Fq4v5I1Vj0HdUCe0zOg+eHgI
qMrZCcS2DwRjaJioo7nsyR65rx1M7Ec/9DOCbEzYxwBbG2PjrvyD2jQk3HcS2V6giwRLGAPwmVUl
s6valuNEg2VajgaRvSyg40bh0isaxQOdFsU514aHs7OlUmmVnvVAlM/WF4R5gzxCdIm5U3OvPNsC
chVqFAPKKywu07gfyrpkvbxB7HrbmMQ3Xi9Sm6SvE0iZAHauoGhr0PVsz4SN3Qps0caIIEAqYPni
Q/1VhgCVdjd9lPhZF4w6aJ8fmpl3ebP4yD+A/hRD1v7x1r5ptrlpg588DiOCkjIskz6sW7l9Uk3I
M88X9KoNQiN5TGTbO/k76f/ClkDZ+7dt0Wq8v9CvK0DQG7BvwKoZJQYMODRwocIBnUKEgDGk0BAY
kebJiCSD4wZBVYJYCBKkQpAPGFBiuIBy5YMHEfoFcPkgXwAEAAQAyEcvwE4AOAEEEBqB5wcLFqpA
ghSxV68zZ0CRIRMv3pgZIMaAgCRjQxAMEQLkFMrzZ86gAcj+/BlzZwC1CMYKVXtWqFu1cevWnVuX
Xj+gAurG3Cu0JgBjP/k+SJiQ4OLF+85MCdFiIoyLkTZu5CpIUBBBR0F+GIRyNIYYGGbmK+YywoN/
/wD3y9cPbD2gdO3+RJDvAokbSREFCiGr6VOpU8dYHZNq3kaTF1zmxu3XcND/voXV/gus9jBPuYhx
S8/r1jYAsD2lx/S+N2Y/enOD7ozQmPHAgfsgtrBocWNGjpurEKmkkj4okKWVLojhgndoC6CflyKA
6TDEvJMOgAeE8uumn17CALSlmHIKKlDiQS65ADHbwALThDJmw/PoyWdDuniaMajzqvtpthjN0nG9
wXC8C62YZgzgvAh++ic+nvIBYEO0hkqooYX2kYyyISK5TDOPBOGys5FECxOld4p55wEFFyymrn/y
eSAmJAW4iS8L62pyLtkeSMeC35RiSpanoioxuV9MwlIGQT5Y8D2zoHTwNvQcBQouKJ3UrVH4YhLq
nyLzmitGvSyNa7Cx5jJm/6wI6qsyhHmaG0KGy/zj7KMgNqiipCBKS0mlGFjrx8yXXAsKALbSQoyw
98oKyj06aXvnKKQgkYw4p9Q5Lh4hTorBMq68KiafHo8VD0o7yyKMOkZJrRSAGIs1NtOfDoMyLbGY
dOvJS+/yLoIJJBhBjF+q2ECj/7jqqEuQbv3ApJQuQBDNCDOM8EFh4SIqJnCHdCu3Y5O1rp9+YghJ
KRCJA1SqeH5hKcuLvLoA2bXwNTZdRtWbS4CaYuzYQVCNxfHe2cRddrC2lLxrR5keQMkCSAT5r2lZ
Z/2ggjBFY4nMd3i9Oi83gxSLr7m045lDseGSr5+QloZEuF5KhooMQlW6gP+ijDZQ6Vu1PkVrsBip
kznn2zLt+yew2g1vLgx5ehkwI+Wi+UdjKwxAwUFG2kzWIAIG00BdVTITJjJnqoe8mmQKoOizmJwL
Lp6Q3Nut0zO1qRi0+xyuuDNoqeIklSzDUneX90rcTq/TFVKoHq3T+1H0ADjdSeK/c9FUvexdXKib
EFByPMMmfQDrAkcKEKQAC9wcJTRBXy06TcMWyja78lISAQGsl8tFw7UfT06dksa8ChmUMoUWhEAd
gYDEwlBSiCx9BgPv2J5b6JcX28wvPNkDgOg6hQBjTK8u8xNAPSb1HePlBnrwyQvytiekd02IMCI0
HHdIRyex4caEnRqhuMT/lqF/CO6DcPEFfNqHqRnmZUIyc+H20JVDGwIlU61Ty7IsJBvBHG6JLzSi
uBI3KhfeaIuls4tZYvfFYREOh7O5UxX1p0UTsstmDnqcdvgWtGIBhidTvKLqjDRFRtXkATrL4uky
5ELEHTF2d6qJbNo4FHj9pEIbilddUHge6XgHkXhry8vio8Qh1bCLO9NZB10nnvOQC3U+UaEL6wef
CpWqXiZsixjNRY/DHOZIuZlUFk9pL7W0xYnv64ng1lVFnCkPMZm6m5wCp8UoEsYsYiGcKknnPEna
RU7yAhfQxBWkckGpmWcRDLhWCa++KPFxyZNL0bZXtEnBJFkIKORcYELM/2rmsJU/qcclBScvUtYJ
k+bZpKcI40f36UZZbfGUbERIR0rBr4qLMyMVe9Kjsk3xXtocFscqFa69YKgnYKuidR4qpHn5iGeL
w6URMQmplIqKgjSqIU+Qx9EAFDGY60GnvIZGzOTBdHGLE10Ig2KqekQwLAHAIALqAZsOJjV716Ne
WMKGwZli8Cz1AKF26DIpYyTVJkd1qk3AKgDYSFVjZdXUpEIIl6a676lmNR39NtXBTZFVLkV9HSRb
9FW4nAWt7WOrxuIKVisONoV3VONhR8jJI6KRsUN0bCchaxNlTvaGlE0sYo2oWBwuVpOcjaxiNWtZ
wqIxnjL8rBadV9jRdv+WWacdYWrRKJt2UVJcQDOhRd1ZPEYadC7YTA8Z9wIW2fRIiu1aZxRtC88Z
yrQ8FEru4My10QyNyj0eZRx8JIldSg3mXbscJ3kMMxQjuc6JNPJLTnKyk0oaT5Y5atQkW5ijMAYv
oDe0kbwmRLw+apGmcVnpSXFT3rjYiYV6QS9d9ptR9NSjiOK1ZRPhy1o8Ms916jIGkzQEFAf3Fkr9
mBEZ+zY9AOeFOocJ4d2eCKonZVc3CG1ReaQoFwpu714zcxLjlrnFOpp2seVEKFk0eBaOzgiORPIU
6W5zs+3izYZyCqcRW+dkhI7qb+jF2bkQE8+OzfcubxKP8PZmSsTgjJRSJj3vXbT8l1fet1MMBaUG
x3PgODfvxgZG7wn/0qnyhPA7RK3LVutsYJyMZ4J+DkuyMpgTPhtDzqCUH40Dfbyc+PV1VywP9A7z
6D83N37PA0BAAAA7"""
ASCII = r" 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#\$%&\'\(\)\*\+,-\./:;<=>\?@\[\]\^_`\{\|\}\\\~\t"

def get_right_member(struct, list_members):
    '''
    Return the right struct member from the list of members (to support a diffrent version).
    '''
    for item in list_members:
        items = item.split('.')
        c_struct = struct
        for sub_item in items:
            if not hasattr(c_struct, sub_item):
                break
            c_struct = getattr(c_struct, sub_item)
        else:
            return c_struct

def strings_ascii(buf, n=5):
    """
    This function extract all the ascii string from a buf where its bigger than n
    yield offset, ascii
    """
    reg = "([%s]{%d,})" % (ASCII, n)
    compiled = re.compile(reg)
    for match in compiled.finditer(buf.decode(errors='ignore')):
        yield hex(match.start()), match.group()#.encode("ascii")

def strings_unicode(buf, n=5):
    """
    This function extract all the unicode string from a buf where its bigger than n
    yield offset, unicode
    """
    reg = bytes(("((?:[%s]\x00){%d,})" % (ASCII, n)).encode()) # place null between them
    compiled = re.compile(reg)
    for match in compiled.finditer(buf):
        try:
            yield hex(match.start()), match.group().decode("utf-16")
        except ZeroDivisionError:
            pass

def get_ascii_unicode(buf, as_string=False ,remove_hex=False, n=5):
    """
    This function return a tuple of (list(strings_ascii), list(strings_unicode))
    """
    if as_string:
        return ['{}: {}'.format(c_offset, c_string) for c_offset, c_string in list(strings_ascii(buf, n))], ['{}: {}'.format(c_offset, c_string) for c_offset, c_string in list(strings_unicode(buf, n))]
    if remove_hex:
        return [c_string for c_offset, c_string in list(strings_ascii(buf, n))], [c_string for c_offset, c_string in list(strings_unicode(buf, n))]
    return list(strings_ascii(buf, n)), list(strings_unicode(buf, n))


class NoteBook(tkinter.ttk.Notebook):
    '''
    NoteBook with the menu that let as to remove tabs.
    '''
    def __init__(self, master, *args, **kwargs):
        tkinter.ttk.Notebook.__init__(self, master, *args, **kwargs)
        self.enable_traversal()

class MemoryInformation(tk.Tk):

    def __init__(self, PageListSummary, PageSummary, FileSummary, get_pfn_info, menu_show='PhysicalRanges', *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.PageListSummary, self.PageSummary, self.FileSummary, self.get_pfn_info = PageListSummary, PageSummary, FileSummary, get_pfn_info
        self.title_font = tkinter.font.Font(family='Helvetica', size=16, weight="bold", slant="italic")
        self.relate = self
        tabcontroller = NoteBook(self)
        self.frames = {}

        for F in (MemoryInfo, FileExplorer, PhysicalRanges, PageColor):
            # __init__ all the classes (the notebook tabs).
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.config()
            frame.grid(row=0, column=0, sticky=E + W + N + S)
            tabcontroller.add(frame, text=page_name)


        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)
        if menu_show in self.frames:
            tabcontroller.select(self.frames[menu_show])
        self.tabcontroller = tabcontroller

class MemoryInfo(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Page List Summary", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        lb_info = tk.Label(self, text="Paging Lists(K)\nZeroed: {}\nFree: {}\nModified: {}\nModifiedNoWrite: {}\nStandby: {}\nPageFileModified: {}".format(self.controller.PageListSummary['MmZeroedPageListHead'] or "", self.controller.PageListSummary['MmFreePageListHead'] or "", self.controller.PageListSummary['MmModifiedPageListHead'] or "", self.controller.PageListSummary['MmModifiedNoWritePageListHead'] or "", self.controller.PageListSummary['MmStandbyPageListHead'] or "", '' or ""))
        lb_info.pack()

class PageColor(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Page Color", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        my_strings = [
            ("NxBit off but marked in vad as not executable (System Excluded): ", "red"),
            ("Non-file executable pages: ", "orange"),
            ("NxBit off but not in vad regions (System Excluded)", "yellow"),
            ("NxBit on but marked in vad as executable ", "purple")
        ]

        self.string_to_tag = {
            my_strings[0][0]:'vad_conflict',
            my_strings[1][0]:'no_file_execute',
            my_strings[2][0]:'execute_no_vad',
            my_strings[3][0]:'ntbit_conflict'
        }

        txt_width = 0
        for c_string in my_strings:
            c_width = tkinter.font.Font().measure(c_string) // 7
            if c_width > txt_width:
                txt_width = c_width
        txt_width = txt_width if txt_width < 250 else 250
        self.buttons = {}
        tlf = tkinter.ttk.Frame(self)
        trf = tkinter.ttk.Frame(self)
        # Create all the labels inside the my_strings list of tuples
        for my_string in my_strings:
            label_txt = my_string[0]
            c_color = my_string[1]

            my_label = tkinter.ttk.Label(tlf, text=label_txt, wraplength=500)#, width=path_button['width'])
            my_label.pack(anchor='w')
            print(label_txt)
            self.buttons[label_txt] = tkinter.Button(trf, width=(txt_width if txt_width < 250 else 250), text='.', bg=c_color, command=functools.partial(self.ChangeColor, label_txt))
            ToolTip(self.buttons[label_txt], "Click To Change Color")
            self.buttons[label_txt].pack(anchor='w')

        tlf.pack(side=LEFT, ipadx=5, padx=5)
        trf.pack(side=LEFT)

    def ChangeColor(self, tag):
        color = tkinter.colorchooser.askcolor()[1]
        self.controller.frames['PhysicalRanges'].tree.tree.tag_configure(self.string_to_tag[tag], background=color)
        self.buttons[tag].configure(bg = color)
        print('Color Changed')

class PhysicalRanges(tk.Frame):

    def __init__(self, parent, controller, data=None):
        global app
        #print('PhysicalRanges Start')
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Page Summary", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        headers = ("Physical Address", "List", "Use", "Priority", "Image", "Offset", "File Name", "Process", "Virtual Address", "NX Bit", "VA in vad")

        self.data = data if data != None else self.controller.PageSummary

        #print(self.data)
        self.tree = TreeTable(self, headers=headers, data=[], resize=False,disable_header_replace='True',text_popup=False, resizeable=False)
        #self.data = data

        self.tree.tree['height'] = 22 if 22 < len(self.data) else len(self.data)
        self.tree.pack(expand=YES, fill=BOTH)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        #print('PhysicalRanges Done')
        #self.aMenu = Menu(self, tearoff=0)
        self.tree.aMenu.add_command(label='HexView', command=self.HexDump)
        self.tree.aMenu.add_command(label='Full Page Info', command=self.PageInfo)
        #self.aMenu.add_command(label='Dump', command=self.Dump)
        #self.tree.tree.bind('<Button-3>', self.popup)
        self.insert_items()
        #app.after(1000, self.insert_items())

    def popup(self, event):
        self.aMenu.post(event.x_root, event.y_root)

    def PageInfo(self):
        item = self.tree.tree.selection()[0]
        print(self.tree.tree.item(item,"text"))
        clicked_addr = int(self.tree.tree.item(item,"text"), 16)
        print(self.tree.tree.item(item)['values'])
        va = self.tree.tree.item(item)['values'][-3]
        app = PI(clicked_addr, va[0] if type(va) is list else va, get_right_member(self.controller, ['get_pfn_info', 'controller.get_pfn_info']))
        app.title('{} ({})'.format('Page Full Info', hex(clicked_addr)))
        #app.main_loop()


    def HexDump(self):
        item = self.tree.tree.selection()[0]
        clicked_file = self.tree.tree.item(item,"text")
        file_handle = open(file_path, 'rb')
        file_handle.seek(int(str(clicked_file).replace('L',''), 16)) # 16 because this is in hex
        file_mem = file_handle.read(0x1000) # Read Page Size.
        file_handle.close()
        app = HexDump(file_name=clicked_file, file_data=file_mem, row_len=16)
        app.title('{} ({})'.format('Memory', clicked_file))
        window_width = 850
        window_height = 650
        width = app.winfo_screenwidth()
        height = app.winfo_screenheight()
        app.geometry('%dx%d+%d+%d' % (window_width, window_height, width*0.5-(window_width/2), height*0.5-(window_height/2)))

    def OnDoubleClick(self, event):
        item = self.tree.tree.selection()[0]
        clicked_file = self.tree.tree.item(item,"text")
        for i in self.controller.PageSummary:
            break

    def insert_items(self):
        """
        This Function insert item to the TreeTable with list first item(if there is list)
        """
        for item in self.data:
            new_item = []
            for i in item:
                if isinstance(item, list):
                    if len(item) > 0:
                        new_item.append(i[0])
                    else:
                        new_item.append('')
                else:
                    new_item.append(i)
            self.tree.tree.insert('', END, values=new_item, text=item[self.tree.text_by_item], tags=item[self.tree.text_by_item])

class Explorer(Frame):
    '''
    Gui class to display explorer like (from dictionary inside dictionary inside dictionary...)
    Each key will be the first item in the table, padding with the tuple that inside the '|properties|' item
    if there is no '|properties|' key in some key the information will be 0 padding
    Thats also mean that you cannot create in your table on the first column a item named "|properties|"
    '''
    def __init__(self, master, my_dict, headers, searchTitle, resize=True, path=None, relate=None, *args, **kwargs):
        Frame.__init__(self, master, *args, **kwargs)

        # Configure gird
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Init var
        self.relate = relate
        self.headers = headers
        self.searchTitle = searchTitle
        self.dict = my_dict

        # Create the top frame (for the buttons and the entry).
        top_frame = tkinter.ttk.Frame(self)

        # Config search button
        self.button_go_back = tkinter.ttk.Button(top_frame, text="<-", command=self.GoBack, width=5)
        ToolTip(self.button_go_back, 'Forward (Alt + Left Arrow)')
        self.button_go_back.pack(side=tk.LEFT)
        self.button_ungo_back = tkinter.ttk.Button(top_frame, text="->", command=self.UnGo, width=5)
        ToolTip(self.button_ungo_back, 'Forward (Alt + Right Arrow)')
        self.button_ungo_back.pack(side=tk.LEFT)
        search_exp_image = tk.PhotoImage(data=EXP_SEARCH_ICON)
        search_exp_image_icon = search_exp_image.subsample(8, 8)
        self.search_button = tk.Button(top_frame, image=search_exp_image_icon, command=self.control_f, height = 20, width = 20)
        self.search_button.search_exp_image_icon = search_exp_image_icon
        self.search_button.pack(side=tk.RIGHT)
        ToolTip(self.search_button, 'Search')

        # Config directory entry
        self.entry_directory = tkinter.ttk.Entry(top_frame)
        self.entry_directory.bind("<KeyRelease>", self.KeyRelease)
        self.entry_directory.bind("<FocusOut>", lambda e: self.after(250, self.FoucusOut))
        self.entry_directory.bind("<Return>", self.LVEnter)
        self.entry_directory.pack(fill='x', ipady=1, pady=1)
        self.c_selection = 0

        top_frame.pack(side=tk.TOP, fill='x')

        # Get all the data
        data, directories = self.GetDataAndDirectories(self.dict)

        # Init stuff like button, tree and bind events
        self.current_directory = ""
        self.last_data = self.last_tw = self.tw = None
        self.directory_queue = []
        self.directory_requeue = []
        self.tree = TreeTable(self, headers=headers, data=data, resize=resize)
        self.tree.tree['height'] = 22 if 22 < len(data) else len(data)
        self.tree.pack(expand=YES, fill=BOTH)
        self.tree.tree.bind("<Alt-Left>", self.GoBack)
        self.tree.tree.bind("<BackSpace>", self.GoBack)
        self.tree.tree.bind("<Alt-Right>", self.UnGo)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        self.tree.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.tree.bind('<Control-f>', self.control_f)
        self.tree.tree.bind('<Control-F>', self.control_f)
        if has_csv:
            self.tree.HeaderMenu.delete(5)
            self.tree.HeaderMenu.insert_command(5, label='Export Explorer To Csv', command=self.export_table_csv)

        # Tag the directories with "tag_directory" so all will be colored with yellow
        def _from_rgb(rgb):
            '''
            Translates an rgb tuple of int to a tkinter friendly color code
            '''
            return "#%02x%02x%02x" % rgb
        self.tree.tree.tag_configure('tag_directory', background=_from_rgb((252, 255, 124)))
        self.tree.visual_drag.tag_configure('tag_directory', background=_from_rgb((252, 255, 124)))

        # Tag all the directories (inside the directories list) with the "tag_directory".
        for i in self.tree.tree.get_children():
            dir_name = self.tree.tree.item(i,"text")

            # Insert the directory to colored tag
            if dir_name in directories:
                self.tree.tree.item(i, tags="tag_directory")
                self.tree.visual_drag.item(i, tags="tag_directory")

        # Go to the path specify if specify
        if path:
            self.GoToFile(path, True)
        else:

            # If the first explorer have only one item go inside this item (recursively).
            change_path = ''
            while len(my_dict) == 1:
                self.directory_queue.append(change_path)
                change_path = '{}\\{}'.format(change_path, list(my_dict.keys())[0])
                my_dict = my_dict[list(my_dict.keys())[0]]

            # Go to the directory.
            #self.GoTo(change_path)

        # Bind exit if this is toplevel.
        if not relate or self.winfo_toplevel() != relate:
            def on_exit():
                self.DetroyLV()
                self.master.destroy()

            # Exit the popup list.
            self.winfo_toplevel().protocol("WM_DELETE_WINDOW", on_exit)

    def control_f(self, event=None):
        '''
        This function spawn the search window.
        :param event: None
        :return: None
        '''
        app = ExpSearch(controller=self, dict=self.dict, dict_headers=self.headers)
        x = self.relate.winfo_x() + 333
        y = self.relate.winfo_y()
        app.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
        app.title(self.searchTitle)
        app.geometry("500x300")

    def export_table_csv(self):
        ''' Export the table to csv file '''
        ans = messagebox.askyesnocancel("Export to csv",
                                        "Did you mean to export all the explorer data or just this specific table?\npress yes to all the data", parent=self)
        if ans == None:
            return

        selected = tkinter.filedialog.asksaveasfilename(parent=self)
        if selected and selected != '':

            def export_specific_dict(csv_writer, dict, path):

                # Go all over the dictionary.
                for key in dict:

                    # Return if this is the information key.
                    if key == '|properties|':
                        continue

                    # If we want to export all the data or just the current
                    if ans:
                        csv_writer.writerow(['{} {}'.format('~' * path.count('\\'), key)] + (list(dict[key]['|properties|']) if '|properties|' in dict[key] else [0 for i in range(len(self.headers)-1)]))
                    elif path == self.current_directory:
                        csv_writer.writerow(['{} {}'.format('~' * path.count('\\'), key)] + (list(dict[key]['|properties|']) if '|properties|' in dict[key] else [0 for i in range(len(self.headers)-1)]))
                        continue
                    elif not path.lower() in self.current_directory.lower():
                        return

                    export_specific_dict(csv_writer, dict[key], '{}\{}'.format(path, key))


            with open(selected, 'w') as fhandle:
                csv_writer = csv.writer(fhandle)
                csv_writer.writerow(self.headers)
                export_specific_dict(csv_writer, self.dict, '')

    def GetDBPointer(self, path, not_case_sensitive=False, return_none_on_bad_path=False):
        '''
        Return the specific dictionary (inside the db dict [self.dict]) that describe the given path
        :param path: the path to describe
        :param not_case_sensitive: False - > case sensitive
        :return: db pointer dictionary somewhere inside the dictionary that describe the given path.
        '''
        db_pointer = self.dict
        path_list = path.split("\\")

        # Remove none item.
        if path_list[0] == '':
            path_list = path_list[1:]

        # Return in empty path.
        if return_none_on_bad_path and len(path_list) == 0:
            return

        current_path = ''
        index = 0
        for key in path_list:
            if key in db_pointer:
                db_pointer = db_pointer[key]

            # Search with lower case
            elif not_case_sensitive:
                for c_key in db_pointer:
                    if c_key.lower() == key.lower():
                        db_pointer = db_pointer[c_key]
                        break
                else:

                    if len(path_list) == index+1:
                        continue

                    if return_none_on_bad_path:
                        return

                    # Unable to find the full go_to path
                    ans = messagebox.askyesnocancel("Notice",
                                                    "Unnable to find this path ({}),\n\nThis path found: {}\nDo you want to go there?".format(
                                                        path, current_path), parent=self)
                    if not ans:
                        return
                    else:
                        # Set the curernt directory.
                        self.current_directory = current_path
                        self.entry_directory.delete(0, tk.END)
                        self.entry_directory.insert(0, self.current_directory)
                        return db_pointer

            elif return_none_on_bad_path and len(path_list) -1  > index:
                return
            index += 1
            current_path += '\{}'.format(key)

        # Set the curernt directory.
        self.current_directory = path
        self.entry_directory.delete(0, tk.END)
        self.entry_directory.insert(0, self.current_directory)
        return db_pointer

    def GetDataAndDirectories(self, db_pointer):
        '''
        Return the data, directory for a given pointer in the dictionary db
        data - > the data sould be displayed for the db_pointer directory
        directories - > is the directories that inside the data
        :param db_pointer: pointer in the directory db (self.my_dict)
        :return: (data, directories)
        '''
        data = []
        directories = []
        for key in list(db_pointer.keys()):

            # Get all the data from the "|properties|" key in each dictionary key that have properties (informatio)
            if key != "|properties|":

                # Get the row items from the "|properties|" key.
                # Pad with zero in case there is no "|properties|" key.
                if "|properties|" in db_pointer[key]:
                    my_tup = db_pointer[key]["|properties|"]
                else:
                    my_tup = tuple([0 for i in range(len(self.headers) - 1)])

                # If this is directory insert it to the directories list witch will be colored in yellow.
                if len(db_pointer[key]) - ("|properties|" in db_pointer[key]) > 0:
                    directories.append(key)

                # Append the key name to the tuple.
                my_tup = (key,) + my_tup if type(my_tup) == tuple else (key, str(my_tup))

                # Insert the spesific row to the list of all the rows.
                data.append(my_tup)
        return data, directories

    def KeyRelease(self, event=None):
        '''
        Display all the directories inside the current directory
        :param event: None
        :return: None
        '''
        data = self.entry_directory.get()

        # If key down or up or left or right or enter return and let the other handle handle it.
        if event and event.keysym_num in [65361, 65362, 65363, 65293]:
            return
        elif event and event.keysym_num in [65364, 65307] and self.tw and self.tw.winfo_exists(): # Key down

            # If ESC pressed detroyd the window and return
            if event.keysym_num == 65307:
                self.DetroyLV()

            return

        # Return if non printable key pressed (nothing add to the entry_directory).
        elif event and event.keysym_num != 65364:# and self.tw:
            if data == self.last_data:
                return

        if self.tw:
            self.DetroyLV()

        # Add the \ if the entry is empty.
        if data == '':
            data = '\\'

        self.last_data = data

        db_pointer = self.GetDBPointer(data, True, return_none_on_bad_path=True)

        # Alert the user that this path not exist (except if he try to delete).
        if not db_pointer:
            if not (event and event.keysym.lower() == 'backspace'):
                self.bell()
                messagebox.showerror('Error', 'Explorer Can\'t Find {},\nCheck the spelling and try again.'.format(data), parent=self)
            return

        values = []

        # Get all the good directories based on the user type.
        for dir in self.GetDataAndDirectories(db_pointer)[1]:
            c_path = '{}\\{}'.format(data[:data.rfind('\\')], dir)

            # Good data
            if data.lower() in c_path.lower():
                values.append(c_path)

        # If there is more than one dir than post.
        if len(values) > 0:

            # Get position to post the toplevel.
            x = self.entry_directory.winfo_rootx()
            y = self.entry_directory.winfo_rooty() + 20

            # Create the top level with frame.
            self.last_tw = str(self.tw)
            self.tw = tw = tk.Toplevel()
            self.my_frame = tkinter.ttk.Frame(self.tw, width=self.entry_directory.winfo_reqwidth() - 1)
            self.values = values
            tw.wm_overrideredirect(1)
            tw.wm_geometry("+%d+%d" % (x, y))

            # Create and pack the listbox with scrollbar
            self.lv = lv = tk.Listbox(self.my_frame, height = len(values) if len(values) < 10 else 10)
            self.scrollbar = scrollbar = Scrollbar(self.my_frame, orient="vertical")
            scrollbar.config(command=self.lv.yview)
            scrollbar.pack(side=tk.RIGHT, fill="y")
            self.lv.config(yscrollcommand=scrollbar.set)
            lv['selectmode'] = tk.SINGLE

            # Bind commands.
            self.entry_directory.bind("<Return>", self.LVEnter)
            self.entry_directory.bind('<Up>', self.Up)
            self.entry_directory.bind('<Down>', self.Down)

            # Insert data to the list (all the pathes).
            for dis in values:
                lv.insert(END, dis)

            # Select the first item.
            lv.selection_set(0)

            # Bind Escape - > destroy and click -> open to the listbox.
            lv.bind("<Escape>", self.DetroyLV)
            #lv.bind('<Button-1>', self.LVEnter)
            lv.bind('<ButtonRelease-1>', self.LVEnter)

            # pack all the data.
            lv.pack(fill=tk.BOTH)
            self.my_frame.pack(fill=tk.BOTH)
            self.update()

            # Windows destroyed..
            try:
                h = self.lv.winfo_geometry().split('x')[1].split('+')[0]
                tw.geometry("{}x{}".format(self.entry_directory.winfo_width() - 2, h))
            except tk.TclError:
                pass

    def Down(self, event):
        '''
        KeyDown event - set selection to one down item
        :param event: None
        :return: None
        '''

        # Cleare the selected item
        self.lv.selection_clear(self.c_selection)

        # Add one if we less or equals to the number of elements in the list else 0
        self.c_selection = self.c_selection + 1 if self.c_selection < len(self.values) - 1 else 0

        # Go to view the item and select.
        self.lv.yview(self.c_selection)
        self.lv.selection_set(self.c_selection)

    def Up(self, event):
        '''
        KeyUp event - set selection to one up item
        :param event: None
        :return: None
        '''
        # If we on the top destroyed.
        if self.c_selection == 0:
            self.DetroyLV()
            return

        # Set selection and position to the selected item.
        self.lv.selection_clear(self.c_selection)
        self.c_selection -= 1
        self.lv.yview(self.c_selection)
        self.lv.selection_set(self.c_selection)

    def LVEnter(self, event=None):
        '''
        On enter/ click go to the selected item set the directory entry and detroyed the listbox.
        :param event: None
        :return: None
        '''

        # Check if we exit the window and this didnt destroyd
        if not self.entry_directory.winfo_exists():
            self.tw.destroy()
            return

        # If there is no goto and popup return.
        if self.tw and len(self.lv.curselection()) != 0:
            go_to = self.lv.get(self.lv.curselection())
        else:
            go_to = self.entry_directory.get()

        # Go to the self.entry_directory.
        self.GoTo(go_to, True)

        # Update the entry directory (add \ to the end and generate keyrelease).
        if not self.current_directory.endswith('\\'):
            self.entry_directory.delete(0, tk.END)
            self.entry_directory.insert(0, '{}\\'.format(self.current_directory))

        self.KeyRelease(None) #self.entry_directory.event_generate('<KeyRelease>')

        self.entry_directory.focus_set()

    def FoucusOut(self, event=None):
        '''
        If we not focus some element of the toplevel exit.
        :param event: None
        :return: None
        '''

        # Check if we focus out the entry and the top level or some of his elements.
        if self.tw and not self.focus_get() in [self.last_tw, self.tw, self.my_frame, self.lv, self.scrollbar] and not self.entry_directory.focus_get().__class__ == tkinter.ttk.Entry:
            self.DetroyLV()

    def DetroyLV(self, event=None):
        '''
        Destroyd the listbox and unbind all the current unnecessary binding methonds.
        :param event:
        :return:
        '''

        # Do this only if the top exist.
        if self.tw and self.tw:
            self.tw.destroy()
            self.tw = None
            #del self.tw
            self.c_selection = 0
            #self.entry_directory.bind('<Return>', lambda e: 'break')
            self.entry_directory.bind("<Return>", self.LVEnter)
            self.entry_directory.bind('<Up>', lambda e: 'break')
            self.entry_directory.bind('<Down>', lambda e: 'break')

    def OnDoubleClick(self, event):
        '''
        This function open directory (replace all the items in the tree to the subdirectory that was double clicked).
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return

        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0 :
            return

        # Get the selected item
        item = self.tree.tree.selection()[0]
        clicked_file = self.tree.tree.item(item, "text")
        tags = self.tree.tree.item(item, "tags")
        if not 'tag_directory' in tags:
            return

        # Append the current directory to the last visited directory list (self.directory_queue).
        self.directory_queue.append(self.current_directory)

        # Change the current directory
        if self.current_directory.endswith('\\'):
            self.current_directory += clicked_file
        else:
            self.current_directory += "\{}".format(clicked_file)

        # Get the selected item from the database dictionary.
        path = self.current_directory
        db_pointer = self.GetDBPointer(path)

        # Get all the data
        data, directories = self.GetDataAndDirectories(db_pointer)

        # Validate that this is directory (more that 0 files inside)
        if len(data) > 0:

            # Reset the undo list
            self.directory_requeue = []

            # Delete the previews data
            for i in self.tree.tree.get_children():
                self.tree.tree.delete(i)
                self.tree.visual_drag.delete(i)

            # Insert the new data.
            self.tree.insert_items(data)

            # Append the all the directories from the directories_list to the tag_directory (so they will colored as directory).
            for i in self.tree.tree.get_children():
                dir_name = self.tree.tree.item(i,"text")
                if dir_name in directories:
                    self.tree.tree.item(i, tags="tag_directory")
                    self.tree.visual_drag.item(i, tags="tag_directory")

    def UnGo(self, event=None):
        '''
        This function is undo fore goback.
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Check that the directory_queue is not empty (the list of the directories history).
        if len(self.directory_requeue) > 0:

            # Go to the last directory.
            prev_dir = self.directory_requeue.pop()
            self.GoTo(prev_dir, True)

    def GoBack(self, event=None):
        '''
        This function go to the previews directory.
        :param event: None
        :return: None
        '''

        # Reset the user search
        self.tree.row_search = ('', 0)

        # Check that the directory_queue is not empty (the list of the directories history).
        if len(self.directory_queue) > 0:

            # Go to the last directory.
            last_dir = self.directory_queue.pop()
            self.GoTo(last_dir, True, False)

    def GoTo(self, go_to, not_case_sensitive=False, go_back=True):
        '''
        This function go to a spesific specified path
        :param goto: path to go (string)
        :param not_case_sensitive: if to check not as case sensetive.
        :param go_back: are we go back or forward.
        :return: None
        '''

        # Add to the right queue (go back or forward).
        if go_back:
            self.directory_queue.append(self.current_directory)
        else:
            self.directory_requeue.append(self.current_directory)

        # Get the selected item from the database dictionary.
        db_pointer = self.GetDBPointer(go_to, not_case_sensitive)

        # If the user dont want to go to the location (because the location doesn't exist in the dump).
        if not db_pointer:
            return

        # Delete current displayed data from the treeview.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

        # Get all the data
        data, directories = self.GetDataAndDirectories(db_pointer)

        # Insert the data and tag the directories as directory.
        self.tree.insert_items(data)
        for i in self.tree.tree.get_children():
            dir_name = self.tree.tree.item(i, "text")
            if dir_name in directories:
                self.tree.tree.item(i, tags="tag_directory")
                self.tree.visual_drag.item(i, tags="tag_directory")

    def GoToFile(self, file_path, not_case_sensitive):
        '''
        Go to the directory and select the file.
        :param file_path: the file path
        :param not_case_sensitive: not case sensitive
        :return: None
        '''

        # Go to the directory.
        go_to = file_path[:file_path.rfind('\\')+1]
        self.GoTo(go_to, not_case_sensitive)

        # Go all over the items and select the right one.
        file_name = file_path[file_path.rfind('\\')+1:]
        for ht_row in self.tree.tree.get_children():
            if str(self.tree.tree.item(ht_row)['values'][0]).lower() == str(file_name).lower():
                self.tree.tree.focus(ht_row)
                self.tree.tree.selection_set(ht_row)
                self.tree.tree.see(ht_row)

class FileExplorer(Explorer):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Files Summary", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        self.exp = Explorer(self, controller.FileSummary, ("File Path", "File Type", "Size"), 'Search File', relate=self)
        self.exp.pack(expand=YES, fill=BOTH)
        self.controller = controller
        self.dict = self.controller.FileSummary
        self.exp.tree.aMenu.add_command(label='View All Pages', command=self.ViewAllPages)


    def ViewAllPages(self):
        item = self.exp.tree.tree.selection()[0]
        clicked_file = self.exp.tree.tree.item(item,"text")
        file_pages = []
        print(clicked_file)
        c_path = self.exp.entry_directory.get() + ("" if self.exp.entry_directory.get().endswith('\\') else '\\')
        clicked_file = '{}{}'.format(c_path, clicked_file)
        print('clicked_file', clicked_file)
        for page_info in self.controller.PageSummary:
            if page_info[6] == clicked_file:
                    file_pages.append(page_info)

        print(file_pages)

        app = tk.Toplevel()
        app.title_font = tkinter.font.Font(family='Helvetica', size=16, weight="bold", slant="italic")
        app.columnconfigure(0, weight=1)
        app.rowconfigure(1, weight=1)
        app.controller = self.controller
        frame = PhysicalRanges(app, app, data=file_pages)
        frame.pack(expand=YES, fill=BOTH)

class PI(tk.Toplevel):

    def __init__(self, addr, va, pfn_info, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.title_font = tkinter.font.Font(family='Helvetica', size=16, weight="bold", slant="italic")
        label = tk.Label(self, text="Page Full Info", font=self.title_font)
        label.pack(side="top", fill="x", pady=10)


        pfn_index = addr >> 12
        pfn_address = pfn_info.get_pfn_from_page_address(addr)
        page_list, priority, reference, share_count, page_color, pte_type, protection, use, file_name, offset, image, pool_tag_list = pfn_info.pfn_info(pfn_address, va=va, pool=True)
        pool_tags = '\n'
        if len(pool_tag_list) > 0:
            for i in pool_tag_list:
                pool_tags+='\t{}: {}'.format(i, POOL_TAGS[i])
        #lb_info = tk.Label(self, text='PFNInfo:\nPFN Index: {} -> PFN Address: {}\nPage_list: {}\nPriority: {}\nReference: {}\nShare Count: {}\nPage Color: {}\nPte Type: {}\nProtection: {}\nUse: {}\nFile Name: {}\nPool Tags:{}\n'.format(index, va, page_list, priority, reference, share_count, page_color, pte_type, protection, use, file_name, pool_tags))
        lb_info = tk.Label(self, text='PFNInfo:\nPFN Index: {} -> PFN Address: {}\nPage_list: {}\nPriority: {}\nReference: {}\nShare Count: {}\nPage Color: {}\nPte Type: {}\nProtection: {}\nUse: {}\nImage:{}\nFile Name: {}\nOffset:{}\nPool Tags:{}\n'.format(pfn_index, pfn_address, page_list, priority, reference, share_count, page_color, pte_type, protection, use, image, file_name, offset, pool_tags))
        lb_info.pack()

#HexDump start

class HexDump(tk.Toplevel):

    def __init__(self,file_name, file_data, row_len, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.title_font = tkinter.font.Font(family='Helvetica', size=16, weight="bold", slant="italic")

        self.row_len = row_len
        self.file_name = file_name
        self.file_data = file_data

        tabcontroller = NoteBook(self)
        self.frames = {}

        # Create all the classes (tabs in the properties).
        for F in (HDHexDump, HDStrings):
            page_name = F.__name__
            frame = F(parent=tabcontroller, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky=E + W + N + S)
            tabcontroller.add(frame, text=page_name)

        tabcontroller.enable_traversal()
        tabcontroller.pack(fill=BOTH, expand=1)

class HDStrings(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Strings", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        data = get_ascii_unicode(self.controller.file_data)
        self.strings_tree = TreeTable(self, headers=("Offset", "ASSCI"), data=data[0], resize=True)
        self.strings_tree.tree['height'] = 22 if 22 < len(data) else len(data)
        self.uni_tree = TreeTable(self, headers=("Offset", "UNICODE"), data=data[1], resize=True)
        self.uni_tree.tree['height'] = 22 if 22 < len(data) else len(data)
        self.strings_tree.pack(expand=YES, fill=BOTH)
        self.uni_tree.pack(expand=YES, fill=BOTH)

class HDHexDump(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="HexDump", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)
        data = []
        ascii = []
        hex_list = []
        count = 0
        for byte in self.controller.file_data:
            hex_list.append("{:02x}".format(byte))
            ascii.append(chr(byte) if 0x20 < byte <= 0x7E else ".")
            if (count % self.controller.row_len) == self.controller.row_len -1:
                data.append((hex(count), "  ".join(hex_list[count - (self.controller.row_len -1):count + 1]), "".join(ascii[count - (self.controller.row_len -1):count + 1])))
            count += 1

        self.values_table = TreeTable(self, headers=("Offset", "Hex", "Data"), data=data, resize=True)
        self.values_table.tree['height'] = 22
        self.values_table.pack(expand=YES, fill=BOTH)
#HexDump end.

class ToolTip(object):
    '''
    the square that apeare when we on widget.
    '''
    def __init__(self, widget, text='help message'):
        # Init Class Variables.
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

        # Event Binding.
        self.widget.bind("<Enter>", self.showtip)
        self.widget.bind("<Leave>", self.hidetip)
        self.widget.bind("<Button-1>", self.hidetip)


    def showtip(self, event=None):
        '''
        Display text in tooltip window (on Enter).
        :param event: None
        :return: None
        '''
        self.event = event
        if self.tipwindow or not self.text:
            return

        # Place the tooltip.
        x, y, cx, cy = self.event.x, self.event.y, self.event.x, self.event.y
        x = x + self.widget.winfo_rootx()+10
        y = cy + self.widget.winfo_rooty()+10
        self.tipwindow = tw = tk.Toplevel()

        # Put the text and pack the tooltip.
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self, event=None):
        '''
        Hide the tip (on leave).
        :param event: None
        :return: None
        '''
        tw = self.tipwindow
        self.tipwindow = None

        # Destroy the tooltip if exist.
        if tw:
            tw.destroy()

class TreeToolTip(object):
    '''
    the square that apeare when we on Treetable(treeview) item.
    '''
    def __init__(self, widget, event):
        self.widget = widget
        self.event = event
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        '''
        Display text in tooltip window (on Enter).
        :param text: text to display
        :return: None
        '''

        self.text = text
        if self.tipwindow or not self.text:
            return

        # Place and pack the tooltip.
        x, y, cx, cy = self.event.x, self.event.y, self.event.x, self.event.y#self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx()+10# + 57#self.widget.x_root + 57
        y = cy + self.widget.winfo_rooty()+10# +27# find the real one.self.widget.y_root + 27
        self.tipwindow = tw = tk.Toplevel()
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=LEFT,
                      background="#ffffe0", relief=SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        '''
        Hide the tip (on leave).
        :return: None
        '''
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class DragAndDropListbox(tk.Listbox):
    ''' A tk listbox with drag'n'drop reordering of entries. '''
    def __init__(self, master, **kw):
        kw['selectmode'] = tk.MULTIPLE
        kw['activestyle'] = 'none'
        tk.Listbox.__init__(self, master, kw)
        self.bind('<Button-1>', self.getState, add='+')
        self.bind('<Button-1>', self.setCurrent, add='+')
        self.bind('<B1-Motion>', self.shiftSelection)
        self.curIndex = None
        self.curState = None

    def setCurrent(self, event):
        ''' gets the current index of the clicked item in the listbox '''
        self.curIndex = self.nearest(event.y)

    def getState(self, event):
        ''' checks if the clicked item in listbox is selected '''
        i = self.nearest(event.y)
        self.curState = self.selection_includes(i)

    def shiftSelection(self, event):
        ''' shifts item up or down in listbox '''
        i = self.nearest(event.y)
        if self.curState == 1:
            self.selection_set(self.curIndex)
        else:
            self.selection_clear(self.curIndex)
        if i < self.curIndex:
            # Moves up
            x = self.get(i)
            selected = self.selection_includes(i)
            self.delete(i)
            self.insert(i+1, x)
            if selected:
                self.selection_set(i+1)
            self.curIndex = i
        elif i > self.curIndex:
        # Moves down
            x = self.get(i)
            selected = self.selection_includes(i)
            self.delete(i)
            self.insert(i-1, x)
            if selected:
                self.selection_set(i-1)
            self.curIndex = i

class MoveLists(tk.Toplevel):
    '''
    2 list box that can move item between them
    '''
    def __init__(self, display, hide, func, *args, **kwargs):
        tk.Toplevel.__init__(self, *args, **kwargs)
        self.display = display
        self.hide = hide
        self.func = func

        frame = Frame(self)
        frame2 = Frame(self)

        frame3 = Frame(frame)
        frame4 = Frame(frame2)

        self.tree1 = DragAndDropListbox(frame3)
        self.tree1.bind("<ButtonRelease-1>", self.update_table)

        self.tree2 = tk.Listbox(frame4, selectmode=tk.MULTIPLE)

        # Insert All the headers to the right tree
        for dis in self.display:
            self.tree1.insert(END, dis)

        for hid in self.hide:
            self.tree2.insert(END, hid)

        button1 = tkinter.ttk.Button(self, text="<- Move Selected ->", command=self.move_table)

        # Pack it all
        button1.pack(padx=10, fill="x", side=tk.BOTTOM)
        tkinter.ttk.Label(frame, text='Display Columns').pack(side=tk.TOP)
        tkinter.ttk.Label(frame2, text='Hide Columns').pack(side=tk.TOP)
        frame3.pack(fill=tk.BOTH)
        frame4.pack(fill=tk.BOTH)
        scrollbar = Scrollbar(frame3, orient="vertical")
        scrollbar.config(command=self.tree1.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.tree1.config(yscrollcommand=scrollbar.set)
        scrollbar = Scrollbar(frame4, orient="vertical")
        scrollbar.config(command=self.tree2.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.tree2.config(yscrollcommand=scrollbar.set)
        self.tree1.pack(side=tk.BOTTOM)
        self.tree2.pack(side=tk.BOTTOM)
        frame.pack(side=tk.LEFT)
        frame2.pack(side=tk.RIGHT)

    def update_table(self, event=None):
        '''
        Call the self.func to update the table.
        :param event: None
        :return: None
        '''
        self.func(None, self.tree1.get(0, END))

    def move_table(self, event=None):
        '''
        Move item from one table to another.
        :param event: None
        :return: None
        '''
        for select in self.tree1.curselection():
            item_text = self.tree1.get(select)
            self.tree2.insert(END, item_text)
        for select in self.tree1.curselection()[::-1]:
            self.tree1.delete(select)

        for select in self.tree2.curselection():
            item_text = self.tree2.get(select)
            self.tree1.insert(END, item_text)
        for select in self.tree2.curselection()[::-1]:
            self.tree2.delete(select)

        self.update_table()

class TreeTable(Frame):
    '''
    treeview like with much more functionality (look like .Net treeview)
    '''
    def __init__(self, master, headers, data, name=None, text_by_item=0, resize=False, display=None, disable_header_replace=600 ,folder_by_item=None, folder_text="?/?", text_popup=True, resizeable=True, global_preference='TreeTable_CULUMNS'):
        """
        master: where to put the treetable.
        header: the columns headers.
        data: the data to put inside.
        text_by_item: the text header of every line (the index in the data in every line).
        resize: True to resize(when the table created or items added).
        display: gets a tuple of all the items to display(from the headers) and display them as default.
        disable_header_replace: sometime we want to disable header (because its slow), so we can give a number of rows or just true. [cant be disable on foldered tree]
        folder_by_item and folder_item used for create a treetable that have foldered some items.n
        folder_by_item: get the item to be the search for the folder_text in the data specific line.
        folder_text: will be the text in the item index to split the items with and go inside the folder tree.
        text_popup: True to enable popup for text when mouse in on some item.
        resizeable: True to resize the table automaticly.
        global_preference: the name for the global variable to put user preference (False/None to disable).
        """
        Frame.__init__(self, master, name=name)

        # Init Class Variables
        self.master = master
        self.resize = resize
        self.text_popup = text_popup
        self.text_by_item = text_by_item
        self.disable_header_replace = disable_header_replace
        self.row_search = ('', 0)
        self.last_seperator_time = 0
        self.swapped = False
        self.current_x = 0
        self.headers = headers
        self.data = data
        self.folder_by_item = folder_by_item
        self.folder_text = folder_text
        self.app_header = None

        # Check if the user put a limit to the header replace (default is 600).
        if disable_header_replace:
            try:
                disable_header_replace = int(disable_header_replace)
                self.disable_header_replace = len(data) > disable_header_replace
            except (TypeError, ValueError):
                self.disable_header_replace = True

        #: :class:`~ttk.Treeview` that only shows "headings" not "tree columns"
        # if the folder_by_item is not null we will go and create a treeview with tree, and seperate them (go deep when folder_text found).
        # for example (('item', 'abc', 'abcd'), ('?/?item2', 'abc', 'abcd'), ('?/?item3', 'abc', 'abcd'), ('?/??/?item4', 'abc', 'abcde'), ('item5', 'abc', 'abcdf'))
        # will create the following tree:
        # | header1 | header2 | header3 |
        # -------------------------------
        # | item1   | abc     | abcd    |
        # | -item2  | abc     | abcd    | item2 will be sub item of item 1
        # | -item3  | abc     | abcd    | item3 will be sub item of item 1 as well
        # | --item4 | abc     | abcde   | item4 will be sub item of item 3
        # | item5   | abc     | abcdf   | item5 dont have any ?/? so he will not be sub item
        if self.folder_by_item != None:
            self.tree = Treeview(self, columns=self.headers, name='tabletree')
            self.tree.heading("#0", text="{} [Total:{}]".format(self.headers[self.folder_by_item], len(data)))
            self.tree["displaycolumns"] = self.headers[:folder_by_item]+self.headers[folder_by_item+1:]
            self.visual_drag = Treeview(self, columns=self.headers, name='visual_drag', show="headings")
            self.visual_drag["displaycolumns"] = self.headers[:folder_by_item] + self.headers[folder_by_item + 1:]
        else:
            self.tree = Treeview(self, columns=self.headers, name='tabletree', show="headings")
            self.visual_drag = Treeview(self, columns=self.headers, name='visual_drag', show="headings")

        # Save the user preference for the display columns (this will override the display if its enable).
        if global_preference:
            if global_preference not in globals():
                globals()[global_preference] = {}

        self.global_preference = global_preference

        self.display = display if display else self.headers
        self.display = globals()[self.global_preference][str(self.headers)] if str(self.headers) in globals()[self.global_preference] else self.display
        self.tree["displaycolumns"] = self.display
        self.visual_drag["displaycolumns"] = self.display

        #: vertical scrollbar
        self.yscroll = Scrollbar(self, orient="vertical",
                                 command=self.tree.yview, name='table_yscroll')
        #: horizontal scrollbar
        self.xscroll = Scrollbar(self, orient="horizontal",
                                 command=self.tree.xview, name='table_xscroll')
        self.tree['yscrollcommand'] = self.yscroll.set  # bind to scrollbars
        self.tree['xscrollcommand'] = self.xscroll.set

        # position widgets and set resize behavior.
        self.tree.grid(column=0, row=0, sticky=(N + E + W + S))
        self.yscroll.grid(column=1, row=0, sticky=(N + S))
        self.xscroll.grid(column=0, row=1, sticky=(E + W))
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Insert all the items and init the title row callbacks (for filtering).
        self._init_title_row_callback()
        self._init_insert_items()
        if len(self.tree.get_children()) > 0:
            self.tree.focus(self.tree.get_children()[0])

        # Set original order to the items (so ctrl+t will restore to default).
        self.original_order = self.get_all_children(self.tree)
        #self.original_order = sorted(self.original_order, key=lambda x: int(str(x[1][0] if isinstance(x[1], tuple) else x[0])[1:], 16))

        # Menu creation.
        self.aMenu = Menu(master, tearoff=0)
        self.HeaderMenu = Menu(master, tearoff=0)
        self.HeaderMenu.add_command(label='Select Columns...', command=self.header_selected)
        self.HeaderMenu.add_command(label='Default Columns', command=self.display_only)
        self.HeaderMenu.add_separator()
        self.HeaderMenu.add_command(label='Hide Column', command=self.hide_selected_col)
        self.HeaderMenu.add_separator()
        if has_csv:
            self.HeaderMenu.add_command(label='Export Table To Csv', command=self.export_table_csv)
            self.HeaderMenu.add_separator()
        if resizeable:
            self.HeaderMenu.add_command(label='Resize Column', command=self.resize_selected_col)
            self.HeaderMenu.add_command(label='Resize All Columns', command=self.resize_all_columns)
        self.copy_menu = Menu(self.aMenu)

        for header in range(len(self.headers)):
            self.copy_menu.add_command(label='{}'.format(self.headers[header]), command=functools.partial(self.RunCopy, header))
        self.aMenu.add_cascade(label='Copy', menu=self.copy_menu)

        """Write Menu (may support in the future..)
        self.write_menu = Menu(self.aMenu)
        for header in range(len(self.headers)):
            self.write_menu.add_command(label='{}'.format(self.headers[header]), command=functools.partial(self.RunWrite, header))
        self.aMenu.add_cascade(label='Write', menu=self.write_menu)
        """

        # Binding keys.
        self.tree.bind('<KeyPress>', self.allKeyboardEvent if self.folder_by_item is None else self.allKeyboardEventTree)
        self.tree.bind("<Double-1>", self.OnDoubleClick)
        self.tree.bind(right_click_event, self.popup)
        self.tree.bind('<Control-c>', self.header_selected)
        self.tree.bind('<Control-C>', self.header_selected)
        self.tree.bind('<Control-t>', self.show_original_order)
        self.tree.bind('<Control-T>', self.show_original_order)

        # header press and release (if disable header replace is disable we still enable them but without the animation).
        self.tree.bind("<ButtonPress-1>", self.bDown)
        self.tree.bind("<ButtonRelease-1>", self.bUp)
        self.tree.bind('<Motion>', self.OnMotion)

        # This binding relevent only if there is virtual drag
        if not self.disable_header_replace:
            self.tree.bind("<<TreeviewOpen>>", self.open_virtual_tree)
            self.tree.bind("<<TreeviewClose>>", self.close_virtual_tree)
            self.tree.bind("<<TreeviewSelect>>", self.set_item)

    def _init_insert_items(self):
        '''
        This function insert item to the table (wheter is a regular table or a treetable).
        :return: None
        '''

        # check if this is folder tree (To make if faster there is big if on the top instead of inside, what makes this kind of duplicated code)
        if self.folder_by_item !=None:

            # Parent dics for the tree
            self.parents_dict = {}

            # the iteretion with resize
            if self.resize:

                # If the user want the header replace drag and drop support.
                if not self.disable_header_replace:

                    self.v_parents_dict = {}

                    # Go all over the data.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').encode('utf-8',errors='ignore').decode('utf-8', errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered or foldered-1 not in self.parents_dict:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        else:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered-1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert(self.v_parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

                        # adjust column's width if necessary to fit each value
                        for idx, val in enumerate(item):
                            col_width = tkinter.font.Font().measure(val)
                            # option can be specified at least 3 ways: as (a) width=None,
                            # (b) option='width' or (c) 'width', where 'width' can be any
                            # valid column option.
                            if self.tree.column(self.headers[idx], 'width') < col_width:
                                self.tree.column(self.headers[idx], width=col_width)
                                self.visual_drag.column(self.headers[idx], width=col_width)
                else:
                    # Go all over the data.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered or foldered-1 not in self.parents_dict:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        else:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

                        # adjust column's width if necessary to fit each value
                        for idx, val in enumerate(item):
                            col_width = tkinter.font.Font().measure(val)
                            # option can be specified at least 3 ways: as (a) width=None,
                            # (b) option='width' or (c) 'width', where 'width' can be any
                            # valid column option.
                            if self.tree.column(self.headers[idx], 'width') < col_width:
                                self.tree.column(self.headers[idx], width=col_width)

            # No resize.
            else:

                # If the user want the header replace drag and drop support.
                if not self.disable_header_replace:

                    self.v_parents_dict = {}

                    # Go all over the data and insert the items.
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').encode('utf-8',errors='ignore').decode('utf-8', errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        elif foldered-1 in self.parents_dict:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered-1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                            self.v_parents_dict[foldered] = self.visual_drag.insert(self.v_parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                else:

                    # Go all over the data and insert the item.s
                    for item in self.data:
                        item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                        c_tag = re.sub('[^\S0-9a-zA-Z]', '_', item[self.text_by_item])
                        foldered = item[self.folder_by_item].count(self.folder_text)
                        item[self.folder_by_item] = item[self.folder_by_item].replace(self.folder_text, "")

                        # If this item sun of no one.
                        if not foldered:
                            self.parents_dict[foldered] = self.tree.insert('', END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)
                        elif foldered - 1 in self.parents_dict:
                            self.parents_dict[foldered] = self.tree.insert(self.parents_dict[foldered - 1], END, text=str(item[self.folder_by_item]), values=item, tags=c_tag, open=True)

        # No headers table.
        else:
            self.insert_items(self.data)

    def _init_title_row_callback(self):
        # build tree
        for col in self.headers:
            # NOTE: Use col as column identifiers, crafty!
            # NOTE: Also change col to title case using str.title()
            # NOTE: make lambda behave nicely in a loop using default arg!
            callback = lambda c=col: self.sortby(c, False)
            self.tree.heading(col, text=col.title(), command=callback)
            self.visual_drag.heading(col, text=col.title())#, command=callback)
            # adjust the column's width to the header string
            self.tree.column(col, width=tkinter.font.Font().measure(col.title()))
            self.visual_drag.column(col, width=tkinter.font.Font().measure(col.title()))

    def insert_items(self, data):
        '''
        This function insert the data to the table
        wrap insert with try except to speedup preformance.
        :param data: list of tuples (the items to insert)
        :return: None
        '''
        # If resize is enable
        if self.resize:

            # Create with visual_drag (for drag and drop support on headers).
            if not self.disable_header_replace:
                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        # This will fail as well (so both table will be in the same item count)
                        try:
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except (Exception, tk.TclError) as ex:
                            pass

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print('[-] Fail to insert {} to the table'.format(item))
                            try:
                                self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            except tk.TclError:
                                pass

                    # adjust column's width if necessary to fit each value
                    for idx, val in enumerate(item):
                        col_width = tkinter.font.Font().measure(val)
                        # option can be specified at least 3 ways: as (a) width=None,
                        # (b) option='width' or (c) 'width', where 'width' can be any
                        # valid column option.
                        if self.tree.column(self.headers[idx], 'width') < col_width:
                            self.tree.column(self.headers[idx], width=col_width)
                            self.visual_drag.column(self.headers[idx], width=col_width)

            # there is no visual_drag
            else:
                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z{}]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print('[-] Fail to insert {} to the table'.format(item))

                    # adjust column's width if necessary to fit each value
                    for idx, val in enumerate(item):
                        col_width = tkinter.font.Font().measure(val)
                        # option can be specified at least 3 ways: as (a) width=None,
                        # (b) option='width' or (c) 'width', where 'width' can be any
                        # valid column option.
                        if self.tree.column(self.headers[idx], 'width') < col_width:
                            self.tree.column(self.headers[idx], width=col_width)

        # If resize is disable.
        else:

            # Create with visual_drag (for drag and drop support on headers).
            if not self.disable_header_replace:

                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):

                        # This will fail as well (so both table will be in the same item count)
                        try:
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except (Exception, tk.TclError) as ex:
                            pass

                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print('[-] Fail to insert {} to the table'.format(item))
                            try:
                                self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                            except tk.TclError:
                                pass
            else:

                # Go all over the data and insert the items
                for item in data:

                    # Add try except to improve performance
                    try:
                        c_tag = str(item[self.text_by_item])
                        self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    except (Exception, tk.TclError):
                        try:
                            item = [str(c_item).replace('{', r'\{').replace('}', r'\}').encode().decode('utf-8',errors='ignore') for c_item in item]
                            c_tag = re.sub('[^\S0-9a-zA-Z{}]', '_', str(item[self.text_by_item]))
                            self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                        except tk.TclError:
                            print('[-] Fail to insert {} to the table'.format(item))

        if len(self.tree.get_children()) > 0:
            self.tree.focus(self.tree.get_children()[0])

        # Set original order to the items (so ctrl+t will restore to default).
        if self.resize:
            self.original_order = self.get_all_children(self.tree)
        self.data += data

    def get_all_children(self, tree, item="", only_opened=True):
        '''
        This function will return a list of all the children.
        :param tree: tree to iterate.
        :param item: from item
        :param only_opened: go only over the items that nop colaps.
        :return: list of all the items [(item, parent), (item, parent)]
        '''
        open_opt = tk.BooleanVar()
        children = []

        # Go all over the childrens
        for child in tree.get_children(item):

            # Append children and parent
            children.append((child, item))
            open_opt.set(str(tree.item(child, option='open')))

            # If only opened items is searched
            if open_opt.get() or not only_opened:
                children += self.get_all_children(tree, child, only_opened)
        return children

    def allKeyboardEvent(self, event):
        '''
        This function go to the item that start with the key pressed by the user (or word), this function search for the current first columns
        if column is moved its will update to the new first column.
        :param event: event
        :return: None
        '''

        # Check for valid key
        if event.keysym_num > 0 and event.keysym_num < 60000:

            # Check if there is any item selected (else select the first one).
            if len(self.tree.selection()) > 0:
                item = self.tree.selection()[0]
            else:
                item = self.tree.get_children('')[0]
            clicked_item = item

            # A timer (for types a words and not just a char.
            if time.time() - self.row_search[1] > 2:
                self.row_search = ('', self.row_search[1])

            # Check for the same character twice in a row.
            if len(self.row_search[0]) == 1 and self.row_search[0][0] == event.char.lower():
                self.row_search = (self.row_search[0][0], time.time())
            else:
                self.row_search = ('{}{}'.format(self.row_search[0], event.char.lower()), self.row_search[1])
            after_selected = False

            # Check all the rows after the current selection.
            for ht_row in self.tree.get_children():
                if clicked_item == ht_row:
                    after_selected = True
                    if time.time() - self.row_search[1] > 2 or len(self.row_search[0]) == 1:
                        continue
                if not after_selected:
                    continue
                if (self.tree["displaycolumns"][0] != '#all' and str(self.tree.item(ht_row)['values'][self.headers.index(self.tree["displaycolumns"][0])]).lower().startswith(self.row_search[0])) or str(self.tree.item(ht_row)['values'][self.text_by_item]).lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            # Check all the rows before the current selection.
            for ht_row in self.tree.get_children():
                if clicked_item == ht_row:
                    break
                if (self.tree["displaycolumns"][0] != '#all' and str(self.tree.item(ht_row)['values'][self.headers.index(self.tree["displaycolumns"][0])]).lower().startswith(self.row_search[0])) or str(self.tree.item(ht_row)['values'][self.text_by_item]).lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            self.bell()
            self.row_search = ('', 0)

    def allKeyboardEventTree(self, event):
        '''
        This function go to the item that start with the key pressed by the user (or word), this function search for the first only!
        :param event: event
        :return: None
        '''

        # Check for valid key
        if event.keysym_num > 0 and event.keysym_num < 60000:
            if len(self.tree.selection()) > 0:
                item = self.tree.selection()[0]
            else:
                item = self.tree.get_children('')[0]
            clicked_item = item
            if time.time() - self.row_search[1] > 2:
                self.row_search = ('', self.row_search[1])

            # Check for the same character twice in a row.
            if len(self.row_search[0]) == 1 and self.row_search[0][0] == event.char.lower():
                self.row_search = (self.row_search[0][0], time.time())
            else:
                self.row_search = ('{}{}'.format(self.row_search[0], event.char.lower()), self.row_search[1])
            after_selected = False

            childrens = self.get_all_children(self.tree)

            # Check all the rows after the current selection.
            for ht_row in childrens:
                ht_row = ht_row[0]
                if clicked_item == ht_row:
                    after_selected = True
                    if time.time() - self.row_search[1] > 2 or len(self.row_search[0]) == 1:
                        continue
                if not after_selected:
                    continue
                if str(self.tree.item(ht_row)['text']).replace(' ','').lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            # Check all the rows before the current selection.
            for ht_row in childrens:
                ht_row = ht_row[0]
                if clicked_item == ht_row:
                    break
                if str(self.tree.item(ht_row)['text']).replace(' ','').lower().startswith(self.row_search[0]):
                    self.tree.focus(ht_row)
                    self.tree.selection_set(ht_row)
                    self.tree.see(ht_row)
                    self.row_search = (self.row_search[0], time.time())
                    return

            self.bell()
            self.row_search = ('', 0)

    def RunCopy(self, cp):
        '''
        Copy the item selected to the clipboard.
        '''
        clip = self.tree
        row = self.tree.selection()[0]
        item = self.tree.item(row)
        clip.clipboard_clear()
        item_text = item['values'][cp]
        clip.clipboard_append(str(item_text))

    def OnMotion(self, event):
        """
        This function handle mouse motion event, on headers moves by the user (drag and drop support). and the tooltip help.
        :param event:
        :return:
        """

        # Handle Motion on dnd column.
        tv = event.widget

        # drag around label if visible
        if self.visual_drag.winfo_ismapped():
            self.swapped = True
            self.last_x = float(self.current_x)
            self.current_x = float(event.x)
            x = self.dx + event.x

            # middle of the dragged column.
            xm = int(x + self.visual_drag.column(self.col_from_id, 'width') // 2)
            self.visual_drag.place_configure(x=x)
            col = tv.identify_column(xm)

            # if the middle of the dragged column is in another column, swap them
            if col and tv.column(col, 'id') != self.col_from_id:
                self.swap(tv, self.col_from_id, col, 'right' if self.current_x - self.last_x > 0 else 'left')

        # Handle tooltip creation
        if self.text_popup:

            # Problem with tk version (just update the version).
            try:

                # Create small square with information
                _iid = self.tree.identify_row(event.y)

                # If hold on table header
                if not _iid or not self.tree.identify_column(event.x)[1:]:
                    return

                item = self.tree.item(_iid)
            except tk.TclError:
                return

            # Hide the current tooltip (if there is any).
            if hasattr(self, "toolTop"):
                self.toolTop.hidetip()

            # Create a tooltip.
            self.toolTop = TreeToolTip(self.tree, event)

            # Find the selected column
            col = int(self.tree.identify_column(event.x)[1:]) -1 if int(self.tree.identify_column(event.x)[1:]) else 0
            text_to_show = ""

            # Make sure to add to the foldered tree's the realy first column info as well so they have more information displayed in the tooltip.
            if self.folder_by_item != None:
                text_to_show = "{}: {}\n".format(self.headers[self.folder_by_item], self.tree.item(_iid)['values'][self.folder_by_item])

            # Get the selected column (acourding to the current display).
            display = self.tree["displaycolumns"]
            text_to_show += "{}: {}".format(self.headers[self.text_by_item], self.tree.item(_iid)['values'][self.text_by_item])


            # If we not on motion on text_by_item column(witch already displayed...).
            if self.headers[self.text_by_item] not in display or col != display.index(self.headers[self.text_by_item]):
                text_to_show += "\n{}: {}".format(display[col], item['values'][self.headers.index(display[col])] if len(item['values']) > self.headers.index(display[col]) else '')
            self.toolTop.showtip(text_to_show)


            def leave(event):
                ''' hide the diplayed tooltip '''
                self.toolTop.hidetip()
            self.tree.bind('<Leave>', leave)

    def swap(self, tv, col1, col2, direction):
        '''
        This function swap 2 columns
        :param tv: treeview
        :param col1: col
        :param col2: col
        :param direction: direction
        :return: None
        '''
        dcols = list(tv["displaycolumns"])

        # When all the columsn is selected we get #all instead of tuples with the names of the row, so lets replace this.
        if dcols[0] == "#all":
            dcols = list(tv["columns"])

        # Get the columns id
        id1 = self.tree.column(col1, 'id')
        id2 = self.tree.column(col2, 'id')

        # Return if one of the columns is not valid (the header column for the folder table).
        if id1 == '' or id2 == '':
            return

        # Get the index of the ids.
        i1 = dcols.index(id1)
        i2 = dcols.index(id2)

        # Return if the columns is not valid (before the first or after the last).
        if (i1 - i2 > 0 and direction == 'right') or (i1 - i2 < 0 and direction == 'left'):
            return

        # Swap.
        dcols[i1] = id2
        dcols[i2] = id1

        # Display in the new order.
        tv["displaycolumns"] = dcols
        self.swapped = True

    def bDown(self, event):
        '''
        This function handle button down event (when we try replace 2 columns).
        :param event:
        :return:
        '''
        tv = tree = event.widget
        left_column = tree.identify_column(event.x)

        # Check if this columns is valid (not the header for folder).
        if left_column[1:] == '':
            return

        right_column = '#%i' % (int(tree.identify_column(event.x)[1:]) + 1)

        # Get the left index
        if (not isinstance(left_column, int)) and (not left_column.isdigit()) and (
                left_column.startswith('I') or left_column.startswith('#')):
            left_column = int(left_column[1:])
        left_column -= 1

        # This is the text header of the treeview(the left column if text header present).
        if left_column != -1:
            left_column = self.headers.index(self.tree["displaycolumns"][left_column])
            width_l = tree.column(left_column, 'width')
            self.visual_drag.column(left_column, width=width_l)

        # Get the right column
        if (not isinstance(right_column, int)) and (not right_column.isdigit()) and (
                right_column.startswith('I') or right_column.startswith('#')):
            right_column = int(right_column[1:])
        right_column -= 1

        # This is the text header of the treeview(the left column if text header present).
        if right_column < len(self.tree["displaycolumns"]):
            right_column = self.headers.index(self.tree["displaycolumns"][right_column])
            width_r = tree.column(right_column, 'width')
            self.visual_drag.column(right_column, width=width_r)

        # Problem with tk version minumum support 8.5.
        try:
            c_region = tv.identify_region(event.x, event.y)
        except tk.TclError:
            c_region = 'heading' if event.y < 26 else 'not good tk version'

        # Check the user select the header of the table.
        if c_region == 'heading':
            self.swapped = False
            col = tv.identify_column(event.x)
            self.col_from_id = tv.column(col, 'id')

            # Iterate all the treeview only if we have not disable header replace.


            # get column x coordinate and width
            if self.col_from_id and self.col_from_id != 0:
                all_children = tv.get_children() #self.get_all_children(tv)
                for i in all_children:
                    bbox = tv.bbox(i, self.col_from_id) #bbox = tv.bbox(i[1][0] if isinstance(i[1], tuple) else i[0], self.col_from_id)
                    if bbox:
                        self.dx = bbox[0] - event.x  # distance between cursor and column left border
                        #        tv.heading(col_from_id, text='')
                        def set_y(*args):
                            self.visual_drag.yview_moveto(self.yscroll.get()[0])

                        def set_y2(event):
                            shift = (event.state & 0x1) != 0
                            scroll = -1 if event.delta > 0 else 1
                            if shift:
                                self.visual_drag.xview_scroll(scroll, "units")
                            else:
                                self.visual_drag.yview_scroll(scroll, "units")

                        # Check if we display beautiful header or not
                        if not self.disable_header_replace:
                            self.visual_drag.configure(displaycolumns=[self.col_from_id], yscrollcommand=set_y)
                            self.tree.bind("<MouseWheel>", set_y2)
                            self.visual_drag.place(in_=tv, x=bbox[0], y=0, anchor='nw', width=bbox[2], relheight=1)
                            self.visual_drag.selection_set(tv.selection())
                            self.visual_drag.yview_moveto(self.yscroll.get()[0])
                        else:
                            self.visual_drag.configure(displaycolumns=[self.col_from_id])
                            self.visual_drag.place(in_=tv, x=event.x, y=0, anchor='nw', width=bbox[2], relheight=1)
                        return

        else:
            self.col_from_id = None

            # Reset the timer (if we select seperator).
            if c_region == 'separator':
                self.last_seperator_time = time.time()

    def bUp(self, event):
        ''' This function hide the visual drage when the courser is up'''
        self.visual_drag.place_forget()

    def open_virtual_tree(self, event):
        ''' This function open the visual_drag when the regulare tree is open'''
        if len(self.tree.selection()) > 0:
            self.visual_drag.item(self.tree.selection()[0], open=1)

    def close_virtual_tree(self, event):
        ''' This function close the visual_drag when the regulare tree is close'''
        if len(self.tree.selection()) > 0:
            self.visual_drag.item(self.tree.selection()[0], open=0)

    def set_item(self, event):
        ''' This function set the selection item in te visual_drag when the regulare tree is selection is change'''
        if len(self.tree.selection()) > 0:
            item = self.tree.selection()[0]
            self.visual_drag.selection_set(item)
            self.tree.focus(item)
            self.tree.see(item)

    def OnDoubleClick(self, event):
        ''' This function handle double click press (for header resize)'''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.identify_region(event.x, event.y) == 'separator':
                    self.resize_col(self.tree.identify_column(event.x))
            except tk.TclError:
                pass # This Tkinter version dont support identify region event.

    def resize_col(self, col):
        '''
        This function resize some collumn.
        :param col: the col to resize (fix size).
        :return: None
        '''
        if (not isinstance(col, int)) and (not col.isdigit()) and (col.startswith('I') or col.startswith('#')):
            col = int(col[1:])
        col -= 1#col-1 if col!=0 else 0

        # This is the text header of the treeview(the left column if text header present).
        if col == -1:
            return
        col = self.headers.index(self.tree["displaycolumns"][col])
        max_len = 0

        # Get the beggest line and resize
        for row in self.get_all_children(self.tree):
            row = row[0]
            item = self.tree.item(row)
            current_len = tkinter.font.Font().measure(str(item['values'][col]))
            if current_len > max_len:
                max_len = current_len
        self.tree.column(self.headers[col], width=(max_len))

        if not self.disable_header_replace:
            self.visual_drag.column(self.headers[col], width=(max_len))

    def display_only(self, event=None, display=None):
        ''' This function display only the wanted items (and save them)'''
        self.tree["displaycolumns"] = display if display else self.display

        if not self.disable_header_replace:
            self.visual_drag["displaycolumns"] = display if display else self.display

        if self.global_preference and display:
            globals()[self.global_preference][str(self.headers)] = display

    def header_selected(self,event=None):
        ''' This function display the move list for header selected '''

        def on_exit():
            ''' Delete the header app when he die and set to None'''
            self.app_header.destroy()
            self.app_header = None

        # If the user select to display the select columns just pop it up (if its exist, else create it).
        if self.app_header:
            self.app_header.attributes('-topmost', 1)
            self.app_header.attributes('-topmost', 0)
        else:

            # Get the current displayed columns.
            display = self.tree["displaycolumns"]

            # Get the current hiden columns
            hide = [item for item in self.headers if item not in self.tree["displaycolumns"]]

            # Remove the first header if this a folder treeview (unsupported).
            if self.folder_by_item != None:
                hide.remove(self.headers[self.folder_by_item])

            # Create the movelists gui.
            self.app_header = MoveLists(display, hide, self.display_only)
            x = self.winfo_x()
            y = self.winfo_y()
            self.app_header.geometry("+%d+%d" % (x + ABS_X, y + ABS_Y))
            self.app_header.resizable(False, False)
            self.app_header.title("Select Columns")
            self.app_header.protocol("WM_DELETE_WINDOW", on_exit)

    def hide_selected_col(self):
        ''' This functio handle the hide column header menu function'''
        display = list(self.tree["displaycolumns"])
        col = self.tree.identify_column(self.HeaderMenu.c_event.x)
        if (not isinstance(col, int)) and (not col.isdigit()) and (col.startswith('I') or col.startswith('#')):
            col = int(col[1:])
        col -= 1

        # This is the text header of the treeview(the left column if text header present).
        if col == -1:
            return
        col = self.tree["displaycolumns"][col]

        display.remove(col)
        self.display_only(None, display)

    def resize_selected_col(self):
        ''' This function handle the resize column from the menu of the table header '''
        self.resize_col(self.tree.identify_column(self.HeaderMenu.c_event.x))

    def resize_all_columns(self):
        ''' This funtion resize all the columns (handle the resize all columns from the menu funciton).'''
        for col in range(len(self.tree["displaycolumns"])+1):
            self.resize_col(col)

    def SetColorItem(self, color, item=None, tag=None):
        '''
        This function set a color to a specific item/tag.
        :param color: the new color.
        :param item: item name (optional)
        :param tag: tag name (optional)
        :return: None
        '''

        # Validate that the user give item/tag and set his color.
        if item or tag:
            tag = tag if tag else self.tree.item(item)['values'][self.text_by_item]
            tag = str(tag).replace(' ', '_')
            self.tree.tag_configure(tag, background=color)
            if not self.disable_header_replace:
                self.visual_drag.tag_configure(tag, background=color)

    def export_table_csv(self):
        ''' Export the table to csv file '''
        selected = tkinter.filedialog.asksaveasfilename(parent=self)
        if selected and selected != '':
            with open(selected, 'w') as fhandle:
                csv_writer = csv.writer(fhandle)
                csv_writer.writerow(self.headers)

                # Export acording to if folder or not
                if self.folder_by_item != None:
                    for row in self.data:
                        csv_writer.writerow(row[:self.folder_by_item] + [row[self.folder_by_item].replace(self.folder_text, '~')] + row[self.folder_by_item+1:])
                else:
                    for row in self.data:
                        csv_writer.writerow(row)

    def popup(self, event):
        ''' This function popup the right menu '''

        # Stop swapping if the user moving some header.
        if self.swapped:
            self.bUp(event)

        # If header selected:
        if event.y < 25 and event.y > 0:
            self.HeaderMenu.c_event = event
            self.HeaderMenu.tk_popup(event.x_root, event.y_root)
        else:

            # Select the item and popup menu
            self.tree.selection_set(self.tree.identify_row(event.y))
            if not self.disable_header_replace:
                self.visual_drag.selection_set(self.tree.identify_row(event.y))
            self.aMenu.tk_popup(event.x_root, event.y_root)

    def sortby(self, col, descending):
        '''
        This function sort column
        :param col: column to sort
        :param descending: order True-descending or false-ascending (saved and switch each time)
        :return:
        '''


        # grab values to sort
        if time.time() - self.last_seperator_time < 0.75 or self.swapped:
            self.swapped = False
            return
        data = [(self.tree.set(child[0], col), child)
                for child in self.get_all_children(self.tree)]

        # now sort the data in place (try first to sort by hex value (int is good to) than by string)
        try:
            data = sorted(data, reverse=descending, key=lambda x: int(x[0], 16))
        except (ValueError, TypeError):
            data.sort(reverse=descending)

        for idx, item in enumerate(data):
            self.tree.move(item[1][0], '', idx)
            if not self.disable_header_replace:
                self.visual_drag.move(item[1][0], '', idx)

        # switch the heading so it will sort in the opposite direction
        callback = lambda: self.sortby(col, not descending)
        self.tree.heading(col, command=callback)

    def show_original_order(self, event=None):
        ''' This function show the original order of the tree (created order)'''
        for idx, item in enumerate(self.original_order):
            if isinstance(item[1], tuple):
                item = item[1]
            self.tree.move(item[0], item[1], idx)
            self.visual_drag.move(item[0], item[1], idx)

class ExpSearch(tk.Toplevel):
    '''
    Search for explorer class, handle explorer ctrl+f
    '''
    def __init__(self, headers=('Path', 'Name', 'Value'), dict=None, dict_headers=None, controller=None, *args, **kwargs):#(path,name,value)
        tk.Toplevel.__init__(self, *args, **kwargs)

        # Init variables
        self.headers = headers
        self.dict = dict
        self.dict_headers = dict_headers
        self.controller = controller

        # Init and pack the class gui.
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.search_text = tk.Entry(self)
        self.search_text.insert(10, 'Search text here')
        self.search_text.bind("<Return>", self.search)
        self.search_text.pack()
        self.select_box = Combobox(self, state="readonly", values=self.dict_headers)
        self.select_box.current(0)
        self.select_box.pack()
        self.search_button = tk.Button(self, text="<- Search ->", command=self.search)
        self.search_button.pack(fill='x')
        self.tree = TreeTable(self, headers=headers, data=[], text_by_item=1, resize=True)
        self.tree.pack(expand=YES, fill=BOTH)

        # Bind and focus
        self.tree.tree.bind("<Return>", self.OnDoubleClick)
        self.tree.tree.bind("<Double-1>", self.OnDoubleClick)
        self.search_text.bind("<FocusIn>", self.focus_in)
        self.search_text.focus()

    def focus_in(self, event=None):
        '''
        This function mark all the text inside the text widget for convenience.
        :param event: None
        :return: None
        '''
        self.search_text.selection_range(0, tk.END)

    def OnDoubleClick(self, event):
        '''
        This fucntio go to the selected item in the parent explorer.
        :param event: None
        :return: None
        '''
        # Double click on table header to resize
        if event and event.y < 25 and event.y > 0:
            try:
                if self.tree.tree.identify_region(event.x, event.y) == 'separator':
                    self.tree.resize_col(self.tree.tree.identify_column(event.x))
                return
            except tk.TclError:
                return
        # Double click where no item selected
        elif len(self.tree.tree.selection()) == 0 :
            return

        # Go and select the clicked item.
        item = self.tree.tree.selection()[0]
        clicked_file_path = self.tree.tree.item(item)['values'][0]
        file_name = self.tree.tree.item(item)['values'][1]
        self.controller.GoToFile('{}\{}'.format(clicked_file_path, file_name), False)

    def recurse_search(self, current_path, current_dir_files):
        '''
        A recursive function that go deep inside the dictionary database and look inside the '|properties|' key to find the searched item
        :param current_path: key name (item name in the explorer)
        :param current_dir_files: a pointer to the current dictionary to search inside
        :return: None, its insert the data to the self.found_data (witch later be insert to the table) or call itself recursive inside.
        '''

        # The item the user want to search
        my_index = self.dict_headers.index(self.select_box.get())-1

        try:
            # Go all over the database dictionary.
            for c_file in current_dir_files:

                # If it's not the item properties (this is another database).
                if c_file != '|properties|':

                    # If the user search for the first box (the item name) than we append the data here.
                    if self.dict_headers.index(self.select_box.get()) == 0:

                        # if this data match the user search than insert it
                        if self.text_to_search in c_file.lower():
                            self.found_data.append((current_path, c_file))
                    self.recurse_search('{}\\{}'.format(current_path, c_file),current_dir_files[c_file])

                # If this is the item properties.
                else:

                    # If this is what the user search for than insert the item to the table.
                    if self.text_to_search in str(tuple(current_dir_files[c_file])[my_index]).lower():
                        self.found_data.append((current_path[:current_path.rfind('\\')], current_path[current_path.rfind('\\')+1:], str(tuple(current_dir_files[c_file])[my_index])))
        except RuntimeError:
            self.recurse_search(current_path, current_dir_files)
            self.found_data = list(set(self.found_data))

    def search(self, event=None):
        '''
        The search handle function that summon the self.recursive_search function.
        :return: None, this function will insert all the founded item to the table.
        '''

        self.text_to_search = self.search_text.get().lower()
        print("[+] searching for: {}".format(self.text_to_search), 'in', self.select_box.get(),'index:', self.dict_headers.index(self.select_box.get())-1)

        # Remove previouse searched items.
        for i in self.tree.tree.get_children():
            self.tree.tree.delete(i)
            self.tree.visual_drag.delete(i)

        self.found_data = []

        # Search for files.
        for c_file in self.dict:

            # Go all over the files.
            if c_file != '|properties|':
                self.recurse_search(c_file, self.dict[c_file])

        # Insert all the data to the table
        self.tree.insert_items(self.found_data)

'''
class PtoV(common.AbstractWindowsCommand):
    """ Physical To Virtual """
    def __init__(self, config, pfndb=None, pte_address=None, page_offset=0, original_pte=None, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        # Check if there is already memmap_dict(maybe not the first time this plugin used).
        if hasattr(self, 'memmap_dict'):
            return
        self._config = config
        #self.kaddr_space = utils.load_as(self._config)

        if pfndb:
            self.pfndb = pfndb
        else:
            self.kdbg = win32.tasks.get_kdbg(self.kaddr_space)
            self.pfndb = int(self.kaddr_space.read(self.kdbg.MmPfnDatabase, 8)[::-1].encode("hex"), 16)^ 0xffff000000000000 #??? ^ 0xffff000000000000
        self.pte_address = pte_address
        self.page_offset = page_offset
        self.original_pte = original_pte
        self.kernel_base = 0xffff80000000 # kdbg.???
        self.getMemmap()

    def getMemmap(self):
        """
        Create the self.memmap_dict dictionary which contain mem map from physical to virtual.
        self.memmap_dict = {EPROCESS, {physical address, virual address}}
        """
        self.memmap_dict = {}
        for task in tasks.pslist(self.kaddr_space):  #proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
            if task.UniqueProcessId:
                offset = 0
                task_space = task.get_process_address_space()
                pages = task_space.get_available_pages()
                self.memmap_dict[task] = {}
                print('start map:', task.UniqueProcessId)
                for page_addr, page_size in pages:

                    """
                    # Skip Kernel address space(we have that on System process).
                    if page_addr > self.kernel_base and task.UniqueProcessId != 4:
                        print 'done map:', task.UniqueProcessId
                        break"""
                    pa = task_space.vtop(page_addr)
                    if pa != None:
                        data = task_space.read(page_addr, page_size)
                        if data != None:
                            self.memmap_dict[task][int(pa)] = int(page_addr)#, obj.Object("_MMPFN",self.pfndb + (0x30 * (physical_address >> 12)), self.kaddr_space or task_space))


        def ptov(self, physical_address):
            """
            this function return list of tuples(_EPROCESS, virtual address, physical address)
            """
            all_proc_info = []
            page_offset = physical_address % 0xFFF
            physical_address = physical_address >> 12 << 12
            for task in self.memmap_dict:
                if physical_address in self.memmap_dict[task]:
                    all_proc_info.append((task, self.memmap_dict[task][physical_address], physical_address))
            return all_proc_info

            """
            # The PFN points at a prototype PTE.
            if int(pfn_entry.u4.m('PrototypePte')):
                cb_addr = pfn_entry.OriginalPte.u.Subsect.SubsectionAddress.v()
                subsection = obj.Object("_SUBSECTION", cb_addr, self.kaddr_space)

                pte_size = self.kaddr_space.profile.get_obj_size("_MMPTE")                        
                offset = (pte_address - vad.FirstPrototypePte.v()) / pte_size
                va = offset * 0x1000 + vad.Start + self.page_offset
            
            """

        def calculate(self):
            return ptov()

        def render_text(self, outfd, data):
            outfd.write("Process(Pid): Virtual Address -> Physical Adress")
            for item in data:
                outfd.write("{}({}): {} -> {}".format(item[0].ImageFileName, item[0].UniqueProcessId, item[1], item[2]))
'''

class P2V(interfaces.plugins.PluginInterface):
    """ Fast ptov (using pfndb) """
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config['primary'] = self.context.modules[self.config['kernel']].layer_name
        self.config['nt_symbols'] = self.context.modules[self.config['kernel']].symbol_table_name
        self._config = self.config
        self._config.ADDRESS = self._config.get("ADDRESS", None)
        if self._config.ADDRESS and self._config.ADDRESS.startswith("0x"):
            self._config.ADDRESS = int(self._config.ADDRESS, 16)

        self.kaddr_space = self.config['primary']
        self.kvo = self.context.layers[self.kaddr_space].config["kernel_virtual_offset"]
        self.ntkrnlmp = self._context.module(self.config['nt_symbols'],
                                        layer_name=self.kaddr_space,
                                        offset=self.kvo)


        _pointer_struct = struct.Struct("<Q") if self.ntkrnlmp.get_type('pointer').size == 8 else struct.Struct('I')
        self._pfndb = int(_pointer_struct.unpack(self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmPfnDatabase').address + self.kvo, self.ntkrnlmp.get_type('pointer').size))[0])
        self.get_proc_pdbs()

        self.HighestUserAddress = int(_pointer_struct.unpack(
            self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmHighestUserAddress').address + self.kvo,
                                                self.ntkrnlmp.get_type('pointer').size))[0])

        self.size_of_pte = self.ntkrnlmp.get_type("_MMPTE").size
        self.size_of_pfn = self.ntkrnlmp.get_type("_MMPFN").size
        self.map_process_vads_subsections()

        self.bit_divisions = [12] + [tup[1] for tup in self.context.layers[self.kaddr_space].structure]
        self.table_names = ["Phys"] + [tup[0] for tup in self.context.layers[self.kaddr_space].structure]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.StringRequirement(name='ADDRESS',
                                             description='Address to translate',
                                             optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
                ]

    def get_proc_pdbs(self):
        """
    get all pdbs from _EPROCESS structure
    """
        self.proc_pdbs = {}
        self.pdb_task = {}
        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols']):
            dtb = task.Pcb.DirectoryTableBase

            # Support windows xp
            if type(dtb) is objects.Array:
                dtb = dtb[0]
            self.proc_pdbs[dtb &~0xfff] = {}
            self.pdb_task[dtb &~0xfff] = task

    def map_process_vads_subsections(self):
        """
        get all vads and subsections from a processes
        """
        self.subsections = {}
        self.vads = {}
        # check how to get subsection from a vad (according to the os versio)

        # Go all over the processes and collect all the subsections.
        for c_proc in pslist.PsList.list_processes(context = self.context,
                                                   layer_name = self.config['primary'],
                                                   symbol_table = self.config['nt_symbols']):
            # Go all over vads.
            for vad in c_proc.get_vad_root().traverse():
                subsection = get_right_member(vad, ["Subsection"])
                if not subsection and not self.context.symbol_space.has_symbol("nt_symbols1!KdCopyDataBlock") and not vad.vol.type_name.endswith("_SHORT"):
                    subsection = self.ntkrnlmp.object("_SUBSECTION", vad.vol.offset + vad.vol.size - self.ntkrnlmp.offset)
                if subsection:
                    try:
                        seen_subs = []
                        # Walk the subsection list
                        while subsection not in seen_subs and subsection:
                            seen_subs.append(subsection)
                            start_addr = subsection.SubsectionBase.real

                            # Vads sould not be in userspace
                            if start_addr > self.HighestUserAddress:

                                end_addr = start_addr + (subsection.PtesInSubsection * self.ntkrnlmp.get_type('_MMPTE').size)
                                range = (start_addr, end_addr)
                                if not range in self.subsections:
                                    self.subsections[range] = []
                                self.subsections[range].append((c_proc, vad, subsection))
                            subsection = subsection.NextSubsection
                    except exceptions.InvalidAddressException:
                        pass
                    if not int(c_proc.UniqueProcessId) in self.vads:
                        self.vads[int(c_proc.UniqueProcessId)] = []
                    self.vads[int(c_proc.UniqueProcessId)].append((vad.get_start(), vad.get_end(),vad))

    def get_subsection(self, addr):
        """
        This function return a [_EPROCESS, _MMVAD, _SUBSECTION] from specific subsection address
        """
        # Check if the subsection present
        ranges = []
        for range in self.subsections:

            # Check if the subsection inside the range address
            if addr > range[0] and addr < range[1]:
                ranges.append(self.subsections[range])

        # Return all the subsection_info ranges in a list or empty list
        return ranges

    def ptov_hardware_pte(self, paddr):
        """
        get ptov for hardware pte only.

        Return:
        (virtual_address, process name, pid, dtb)
        """
        p_addr = paddr
        physical_addresses = dict(Phys=p_addr)
        phys_addresses_of_pte = {}
        ptes = {}
        proc = None
        # Go all over the tables
        for i, table_name in enumerate(self.table_names):
            if not PFNInfo.is_pfn_valid(self.context, self.ntkrnlmp, p_addr >> 12):
                return ('Invalid pfn, Translation failed..', 'Invalid pfn, Translation failed..')
            c_pfn = self.ntkrnlmp.object("_MMPFN", self._pfndb + (int(p_addr >> 12) * self.size_of_pfn) - self.kvo)
            pte = get_right_member(c_pfn, ["PteLong", "PteAddress"])
            if i > 0:
                physical_addresses[table_name] = ptes[self.table_names[i - 1]].vol.offset
            p_addr = ((c_pfn.u4.PteFrame << 12) | (pte & 0xFFF))
            phys_addresses_of_pte[table_name] = p_addr
            ptes[table_name] = self.context.object(self._config['nt_symbols'] + constants.BANG + "_MMPTE", "memory_layer", p_addr)
        dtb = p_addr & ~0xFFF

        # Get the process for this dtb.
        if dtb in self.proc_pdbs:
            proc = self.pdb_task[dtb]
        virtual_address = 0
        start_of_page_table = dtb
        size_of_pte = self.ntkrnlmp.get_type("_MMPTE").size

        # Get the va
        for table_name, bit_division in reversed(list(zip(self.table_names, self.bit_divisions))):
            pte = ptes[table_name]
            virtual_address += (ptes[table_name].vol.offset - start_of_page_table) // size_of_pte
            virtual_address <<= bit_division
            start_of_page_table = pte.u.Hard.PageFrameNumber << 12

        virtual_address = self.context.layers['primary'].address_mask & virtual_address
        virtual_address += paddr & 0xFFF
        return virtual_address, proc

    def my_ptov_hardware_pte_x64(self, addr):
        """
        get ptov for hardware pte only.
        This function Work only for AMD64#

        Return:
        (virtual_address, process name, pid, dtb)
        """
        va = int(addr) & 0xFFF	# page offset
        proc = None
        pfn_index = int(addr) >> 12
        for i in range(4):
            c_pfn = self.ntkrnlmp.object("_MMPFN", self._pfndb + (pfn_index * self.size_of_pfn) - self.kvo)
            va += ((c_pfn.PteAddress.vol.offset & 0xFFF) // 8) << (12 + 9 * i)
            pfn_index = c_pfn.u4.PteFrame
            if int(c_pfn.u4.PteFrame) << 12 in self.proc_pdbs:
                proc = self.pdb_task[int(c_pfn.u4.PteFrame) << 12]
        return (hex(va), proc)

    def ptov_prototype_pte(self, addr):
        """
        get ptov for prototype pte with file info.

        Return:
        (virtual_address, file_name, offset, [_EPROCESS, _MMVAD, _SUBSECTION])
        """
        pfn_index = int(addr) >> 12
        pfn = self.ntkrnlmp.object("_MMPFN", self._pfndb + (pfn_index * self.size_of_pfn) - self.kvo)
        page_offset = int(addr) & 0xfff
        pte_address = pfn.PteAddress
        original_pte = pfn.OriginalPte
        subsection = self.ntkrnlmp.object("_SUBSECTION", int(original_pte.u.Subsect.SubsectionAddress) - self.kvo)
        # Check if this is valid subsection
        if subsection.has_valid_member('ControlArea') and subsection.ControlArea.has_valid_member("FilePointer"):
            try:
                file_name = subsection.ControlArea.FilePointer.dereference().cast('_FILE_OBJECT').file_name_with_device()
            except exceptions.InvalidAddressException:
                file_name = 'File Name address invalid (maybe paged out)'
            file_offset = 0x1000 * (pte_address - subsection.SubsectionBase) // self.size_of_pte + (
                                subsection.StartingSector * 512) + page_offset

            # The subsection currentry mapped (WS) to some process.
            subsection_info = self.get_subsection(pte_address.real)
            if subsection_info:
                va_list = []
                e_proc_list = []
                # Go all over the range list
                for sub_info in subsection_info:

                    # Go for eack tuple
                    for e_proc, c_vad, _ in sub_info:
                        #e_proc, c_vad, _= sub_info[-1]	# COULD BE MORE THAN ONE PROCESS!!! CHANGE THIS #FIXME!!
                        relative_offset = (pte_address - c_vad.FirstPrototypePte) // self.size_of_pte
                        va = relative_offset * 0x1000 + c_vad.get_start() + page_offset
                        if va < self.HighestUserAddress or e_proc.UniqueProcessId == 4:
                            va_list.append(va)
                            e_proc_list.append(e_proc)
            if subsection_info and va_list:
                return (va_list, e_proc_list, file_name, hex(file_offset), subsection_info)
            else:
                # If the subsection_list empty (no owner)
                additional_info = self.ptov_hardware_pte(addr)
                return (additional_info[:2] + (file_name, file_offset, [[(None, None, subsection)]]))

        return self.ptov_hardware_pte(addr) + (None, None) + ([[(None, None, None)]],)

    def ptov(self, physical_addr):
        """

        Return:
        va, owner, file_name, file_offset, [(proc, vad, subsection)]
        """
        physical_addr = int(physical_addr, 16) if str(physical_addr).startswith("0x") else int(physical_addr)
        pfn_index = physical_addr >> 12
        if not PFNInfo.is_pfn_valid(self.context, self.ntkrnlmp, pfn_index):
            return ('Invalid pfn, Translation failed..', 'Invalid pfn, Translation failed..') + (None, None) + ([[(None, None, None)]],)
        pfn_entry = self.ntkrnlmp.object("_MMPFN", self._pfndb + (pfn_index * self.size_of_pfn) - self.kvo)
        if int(get_right_member(pfn_entry,["u4.PrototypePte", "u3.e1.PrototypePte"])):
            return self.ptov_prototype_pte(physical_addr)
        else:
            return self.ptov_hardware_pte(physical_addr) + (None, None) + ([[(None, None, None)]],)

    def _generator(self):
        pa, va, owner, file_name, file_offset, additional_info = (hex(self._config.ADDRESS),) + self.ptov(self._config.ADDRESS)
        if type(owner) is list:
            owners = []
            list_pid = []
            for own in owner:
                list_pid.append(str(int(own.UniqueProcessId)))
                owners.append("{} ({})".format(objects.utility.array_to_string(own.ImageFileName), int(own.UniqueProcessId)))
            owner = ", ".join(owners)
            list_pid = ", ".join(list_pid)
        elif owner and (type(owner) is not str):
            list_pid = str(int(owner.UniqueProcessId))
            owner = "{} ({})".format(objects.utility.array_to_string(owner.ImageFileName), int(owner.UniqueProcessId))
        else:
            list_pid = ''
            owner = "There is no owner for this page"

        if type(va) is list:
            va = ", ".join([hex(v) for v in va])
        elif type(va) is int:
            va = hex(va)

        if not file_name:
            file_name = '-'
        if not file_offset:
            file_offset = '-'

        yield (0,(owner, list_pid, file_name, file_offset, pa, va))

    def run(self):
        return renderers.TreeGrid([("Owner", str), ("Loading To", str), ("File Name", str), ("File Offset", str),
                                   ("Physical", str), ("Virtual", str)],
                                  self._generator())

class PFNInfo(interfaces.plugins.PluginInterface):
    """ PFN related information """
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config['primary'] = self.context.modules[self.config['kernel']].layer_name
        self.config['nt_symbols'] = self.context.modules[self.config['kernel']].symbol_table_name
        self.kaddr_space = self.config['primary']
        self._config = self.config

        self._config.ADDRESS = self._config.get("ADDRESS", None)
        self._config.INDEX = self._config.get("INDEX", None)
        self._config.PAGE = self._config.get("PAGE", None)
        self.kvo = self.context.layers[self.kaddr_space].config["kernel_virtual_offset"]
        self.ntkrnlmp = self._context.module(self.config['nt_symbols'],
                                             layer_name=self.kaddr_space,
                                             offset=self.kvo)

        self.size_of_pfn = self.ntkrnlmp.get_type("_MMPFN").size
        _pointer_struct = struct.Struct("<Q") if self.ntkrnlmp.get_type('pointer').size == 8 else struct.Struct('I')
        pfndb = int(_pointer_struct.unpack(self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmPfnDatabase').address + self.kvo, self.ntkrnlmp.get_type('pointer').size))[0])
        self.HighestUserAddress = int(_pointer_struct.unpack(self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmHighestUserAddress').address + self.kvo, self.ntkrnlmp.get_type('pointer').size))[0])
        self.file_path = urllib.request.url2pathname(self.context.config['automagic.LayerStacker.single_location'][file_slice:])
        self.page_file_db = pfndb
        self.get_pool_ranges()
        self.pte_page_protection = {'0': 'MM_ZERO_ACCESS', '1': 'MM_READONLY', '2': 'MM_EXECUTE', '3': 'MM_EXECUTE_READ',
                                    '4': 'MM_READWRITE', '5': 'MM_WRITECOPY', '6': 'MM_EXECUTE_READWRITE',
                                    '7': 'MM_PROTECT_ACCESS', '8': 'MM_NOCACHE', '16': 'MM_GUARDPAGE',
                                    '24': 'MM_PROTECT_SPECIAL', '4294967295': 'MM_INVALID_PROTECTION'}
        if self._config.INDEX:
            if self._config.INDEX.startswith('0x'):
                self._config.INDEX = int(self._config.INDEX, 16)
            self._config.ADDRESS = self.page_file_db + int(self._config.INDEX) * self.size_of_pfn
        elif self._config.ADDRESS:
            if self._config.ADDRESS.startswith('0x'):
                self._config.ADDRESS = int(self._config.ADDRESS, 16)
            self._config.INDEX = ((int(self._config.ADDRESS)) - self.page_file_db) // self.size_of_pfn
        elif self._config.PAGE:
            if self._config.PAGE.startswith('0x'):
                self._config.PAGE = int(self._config.PAGE, 16)
            self._config.INDEX = int(self._config.PAGE) >> 12
            self._config.ADDRESS = self.page_file_db + int(self._config.INDEX) * self.size_of_pfn


    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.StringRequirement(name='ADDRESS',
                                               description='Address of pfn',
                                               optional=True),
                requirements.StringRequirement(name='INDEX',
                                               description='Index of pfn',
                                               optional=True),
                requirements.StringRequirement(name='PAGE',
                                               description='Page Physical Address',
                                               optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
                ]

    @classmethod
    def is_pfn_valid(cls, context, nt, pfn_index):
        """
        Return wheters this pfn index have a valid pfn or not
        """
        try:
            addr = nt.get_symbol('MiPfnBitMap').address
            rtl = nt.object("_RTL_BITMAP", addr)

            # Check if the page index not out of range
            if rtl.SizeOfBitMap < pfn_index:
                return False

            # Check if the page is valid
            c_byte = context.layers['primary'].read(rtl.Buffer + (pfn_index >> 3), 1)[0]
            if c_byte & (2 ** (pfn_index % 8)) == (2 ** (pfn_index % 8)):
                return True
            return False
        except Exception as ex:
            # Could be symbol error (in windows 10)
            _pointer_struct = struct.Struct("<Q") if nt.get_type('pointer').size == 8 else struct.Struct('I')
            kvo = context.layers['primary'].config["kernel_virtual_offset"]
            pfndb = int(_pointer_struct.unpack(context.layers['primary'].read(nt.get_symbol('MmPfnDatabase').address + kvo, nt.get_type('pointer').size))[0])
            pfn_entry = nt.object("_MMPFN", pfndb + (int(pfn_index) * nt.get_type("_MMPFN").size) - kvo)
            try:
                return pfn_entry.u4.PfnExists
            except Exception:
                return False

    def get_pool_ranges(self):
        class PoolDescriptor:
            pass
        self.pools = []
        def get_pointer_from_object(nt, symbol_name, my_struct=None):
            _pointer_struct = my_struct or (struct.Struct("<Q") if nt.get_type('pointer').size == 8 else struct.Struct('I'))
            try:
                return int(_pointer_struct.unpack(
                    nt.context.layers['primary'].read(nt.get_symbol(symbol_name).address + nt.offset,
                                                   nt.get_type('pointer').size))[0])
            except Exception:
                return None

        # Getting NonPagedPool.
        # Windows XP :)
        start_va = get_pointer_from_object(self.ntkrnlmp, 'MmNonPagedPoolStart')
        end_va = get_pointer_from_object(self.ntkrnlmp, 'MmNonPagedPoolEnd')

        if not start_va:
            start_va = get_pointer_from_object(self.ntkrnlmp, 'MiNonPagedPoolStartAligned')

        if not end_va:
            bitmap_addr = get_pointer_from_object(self.ntkrnlmp, 'MiNonPagedPoolBitMap')
            if bitmap_addr:
                bitmap = self.ntkrnlmp.object('_RTL_BITMAP', bitmap_addr)
                end_va = (start_va & self.context.layers['primary'].address_mask) + bitmap.SizeOfBitMap * 8 * 0x1000

        # Windows 10
        if not start_va:
            MiState = self.ntkrnlmp.object('_MI_SYSTEM_INFORMATION', get_pointer_from_object(self.ntkrnlmp, 'MiState'))
            node_info = get_right_member(MiState, ['Hardware.SystemNodeInformation', 'SystemNodeInformation']).cast('_MI_SYSTEM_NODE_INFORMATION')
            start_va = end_va = node_info.NonPagedPoolFirstVa & self.context.layers['primary'].address_mask
            if hasattr(node_info, 'NonPagedPoolLastVa'):
                end_va = node_info.NonPagedPoolLastVa & self.context.layers['primary'].address_mask
            elif hasattr(node_info, 'NonPagedBitMap'):
                bitmap = node_info.NonPagedBitMap
                end_va = max(start_va, start_va + bitmap.SizeOfBitMap * 8)

        NonPagedPool = PoolDescriptor()
        NonPagedPool.start_va = start_va & self.context.layers['primary'].address_mask
        NonPagedPool.end_va = end_va
        NonPagedPool.name = 'NonPagedPool'
        self.pools.append(NonPagedPool)

        # --------------------------------------------------------------------------------#

        # Getting PagedPool.
        # Windows XP :)
        start_va = get_pointer_from_object(self.ntkrnlmp, 'MmPagedPoolStart')

        if not start_va:
            start_va = get_pointer_from_object(self.ntkrnlmp, 'MiPagedPoolStart')

        if start_va:
            end_va = start_va + get_pointer_from_object(self.ntkrnlmp, 'MmSizeOfPagedPoolInBytes')
        else:
            end_va = get_pointer_from_object(self.ntkrnlmp, 'MmPagedPoolEnd')
            addr = get_pointer_from_object(self.ntkrnlmp, 'MmPagedPoolInfo')
            if addr:
                try:
                    bitmap = self.ntkrnlmp('_MM_PAGED_POOL_INFO', addr).PagedPoolAllocationMap
                    start_va = end_va - (bitmap.SizeOfBitMap * 8 * 0x1000)
                except Exception:
                    start_va = end_va - (get_pointer_from_object(self.ntkrnlmp, 'MmSizeOfPagedPoolInBytes'))#, struct.Struct("<Q"))) # unsinged long long

        if not start_va:
            try:
                MiState = self.ntkrnlmp.object('_MI_SYSTEM_INFORMATION', get_pointer_from_object(self.ntkrnlmp, 'MiState'))
                dynamic_paged_pool = get_right_member(MiState, ['SystemVa.DynamicBitMapPagedPool', 'DynamicBitMapPagedPool']).cast(
                    '_MI_SYSTEM_NODE_INFORMATION')
                start_va = dynamic_paged_pool.BaseVa
                end_va = start_va + (dynamic_paged_pool.MaximumSize * 0x1000)
            except Exception:
                pass

        if not start_va:
            if self.context.layers['primary'].metadata.get('architecture') == 'Intel32':
                start_va = end_va = -1 # TODO add win7x86 support
            else:
                # windows 7 64 bit
                start_va = 0xFFFFF8A000000000
                end_va = 0xFFFFF8BFFFFFFFFF

        PagedPool = PoolDescriptor()
        PagedPool.start_va = start_va & self.context.layers['primary'].address_mask
        PagedPool.end_va = end_va & self.context.layers['primary'].address_mask
        PagedPool.name = 'PagedPool'
        self.pools.append(PagedPool)

        # --------------------------------------------------------------------------------#

        # Getting session PagedPool.
        seen_ids = []
        for proc in pslist.PsList.list_processes(context=self.context, layer_name=self.config['primary'], symbol_table=self.config['nt_symbols']):
            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId

                # create the session space object in the process' own layer.
                # not all processes have a valid session pointer.
                session_space = self.context.object(proc.get_symbol_table_name() + constants.BANG + "_MM_SESSION_SPACE",
                                               layer_name=self.config['primary'],
                                               offset=proc.Session)

                if session_space.SessionId in seen_ids:
                    continue

                PagedPool = PoolDescriptor()
                PagedPool.start_va = session_space.PagedPoolStart & self.context.layers['primary'].address_mask
                PagedPool.end_va = session_space.PagedPoolEnd & self.context.layers['primary'].address_mask
                PagedPool.name = 'SessionPagedPool'
                self.pools.append(PagedPool)

            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "Process {} does not have a valid Session or a layer could not be constructed for it".format(
                        proc_id))
                continue

            # save the layer if we haven't seen the session yet
            seen_ids.append(session_space.SessionId)

    def va_in_pool(self, addr):
        for pool_descriptor in self.pools:
            if pool_descriptor.start_va < addr and pool_descriptor.end_va > addr:
                return pool_descriptor.name
        return  False

    def get_physical_from_index(self, index):
        return self.page_file_db + int(index)*self.size_of_pfn

    def get_pfn_from_page_address(self, page_address):
        return self.get_physical_from_index(page_address >> 12)

    def get_page_address(self, pfn_address):
        #print hex(pfn_address)
        pfn_address = int(str(pfn_address).replace('L',''), 16) if type(pfn_address)=='str' else int(pfn_address)
        return ((pfn_address - self.page_file_db)//self.size_of_pfn) << 12#^0xffff000000000000

    def pfn_info(self, pfn_address, va=None, pool=True):

        if va and str(va).startswith('0x'):
            va = int(va, 16)
        elif va:
            va = int(va)
        pfn_entry = self.ntkrnlmp.object("_MMPFN", int(pfn_address) - self.kvo)

        #try:
        pool_tag_list = []
        use = ''
        file_name = 'None'
        offset = 0
        image = False
        page_list = PAGES_LIST[int(pfn_entry.u3.e1.PageLocation)] if int(pfn_entry.u3.e1.PageLocation) in PAGES_LIST else str(pfn_entry.u3.e1.PageLocation)
        priority = get_right_member(pfn_entry.u3, ['e1.Priority', 'e3.Priority']) if get_right_member(pfn_entry.u3, ['e1.Priority', 'e3.Priority']) !=None else "-"
        reference = int(pfn_entry.u3.e2.ReferenceCount)
        share_count = int(pfn_entry.u2.ShareCount)
        page_color = int(get_right_member(pfn_entry, ["u4.PageColor", "u3.e1.PageColor"]))
        pte_type = 'Prototype PTE' if int(get_right_member(pfn_entry,["u4.PrototypePte", "u3.e1.PrototypePte"])) else 'Hardware PTE'
        #protection = self.pte_page_protection[4294967295] if protection not in self.pte_page_protection else self.pte_page_protection[protection]

        if hasattr(pfn_entry.OriginalPte.u.Hard, "NoExecute"):
            protection = int(pfn_entry.OriginalPte.u.Hard.NoExecute)
        else: # 32bit (without awe) don't support NX bit
            protection = -1
        if not va:
            if pool:# and False: # file_handle.seek(page_addr) OverflowError: long too big to convert
                page_addr = self.get_page_address(pfn_address)
                page_data = self.context.layers['memory_layer'].read(page_addr, 0x1000, True)
                #file_handle = open(self.file_path, 'rb') # This only supported on raw memdump
                #file_handle.seek(page_addr)
                #page_data = file_handle.read(0x1000) # Read Page Size.
                #file_handle.close()

                # The data inside the page
                if page_data:

                    # Check if ther is some pool tag inside that page
                    for pool_tag in POOL_TAGS:
                        if pool_tag.encode() in page_data:#use=pool
                            pool_tag_list.append(pool_tag)
                else:
                    print('[-] Empty Page')
            else:
                use = 'Private \ Kernel \ Pool'
            if use == '':
                use = 'Private \ Kernel'
        elif va > self.HighestUserAddress:
            # "This is Kernel | pool"
            test_pool = self.va_in_pool(va)
            if test_pool:
                use = test_pool
                if pool:
                    page_addr = self.get_page_address(pfn_address)
                    file_handle = open(self.file_path, 'rb')
                    file_handle.seek(page_addr)
                    page_data = file_handle.read(0x1000)  # Read Page Size.
                    file_handle.close()

                    # The data inside the page
                    if page_data:

                        # Check if ther is some pool tag inside that page
                        for pool_tag in POOL_TAGS:
                            if pool_tag.encode() in page_data:
                                pool_tag_list.append(pool_tag)
            else:
                use = 'Kernel'
        else:
            use = 'Private'

        # If there is no reference than mark this page as unused.
        if pfn_entry.u3.e2.ReferenceCount == 0:
            use += ", Unused"

        # Try to find file pointer
        cb_addr = int(pfn_entry.OriginalPte.u.Subsect.SubsectionAddress)
        subsection = self.ntkrnlmp.object("_SUBSECTION", cb_addr - self.kvo)
        if subsection.has_valid_member("ControlArea") and subsection.ControlArea.has_valid_member("FilePointer"):
            use = 'Mapped File'
            try:
                file_name = subsection.ControlArea.FilePointer.dereference().cast('_FILE_OBJECT').file_name_with_device()
            except exceptions.InvalidAddressException:
                file_name = 'File Name address invalid (maybe paged out)'

            # Try to get file offset and if its image.
            ca = subsection.ControlArea
            start = subsection.SubsectionBase
            pte_address = pfn_entry.PteAddress
            if ca.u.has_valid_member('Flags'):
                if ca.u.Flags.has_valid_member('Image'):
                    if ca.u.Flags.Image:
                        image = True
                    else:
                        image = False
                if ca.u.Flags.has_valid_member('File') and ca.u.Flags.File:
                    pte_size = self.ntkrnlmp.get_type("_MMPTE").size
                    offset = 0x1000 * (pte_address - start) // pte_size + (subsection.StartingSector * 512)
        return(page_list, priority, reference, share_count, page_color, pte_type, protection, use, file_name, offset, image, pool_tag_list)

    def _generator(self):
        if not self.is_pfn_valid(self.context, self.ntkrnlmp, int(self._config.INDEX)):
            raise ('Invalid pfn, unable to get information about this page')
        data = self.pfn_info(self._config.ADDRESS)
        yield (0, (self._config.INDEX, self._config.ADDRESS) + data[:-1] + (str(data[-1:]),))

    def run(self):
        return renderers.TreeGrid([("PFN Index", str), ("PFN Address", int), ("Page List", str), ("Priority", int), ("Reference", int),
                                   ("Share Count", int), ("Page Color", int), ("Pte Type", str), ("NxBit", int), ("Use", str),
                                   ("File Name", str), ("Offset", int), ("Image", bool), ("Pool Tags", str)],
                                  self._generator())

class RamMap(interfaces.plugins.PluginInterface):
    """Map Physical pages"""
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config['primary'] = self.context.modules[self.config['kernel']].layer_name
        self.config['nt_symbols'] = self.context.modules[self.config['kernel']].symbol_table_name
        self._config = self.config
        self.file_path = urllib.request.url2pathname(self.context.config['automagic.LayerStacker.single_location'][file_slice:])
        self._config.COLORED = self._config.get("COLORED", None)

        self._config.ADDRESS = self._config.get("ADDRESS", None)
        if not self._config.ADDRESS:
            self._config.ADDRESS = 0
        elif self._config.ADDRESS.startswith("0x"):
            self._config.ADDRESS = int(self._config.ADDRESS, 16)
        else:
            self._config.ADDRESS = int(self._config.ADDRESS)
        self._config.ADDRESS = self._config.ADDRESS &~ 0xFFF

        self._config.SIZE = self._config.get("SIZE", None)
        if not self._config.SIZE:
            self._config.SIZE = os.path.getsize(self.file_path) - self._config.ADDRESS
        elif self._config.SIZE.startswith("0x"):
            self._config.SIZE = int(self._config.SIZE, 16)
        else:
            self._config.SIZE = int(self._config.SIZE)

        self.kaddr_space = self.config['primary']
        self.kvo = self.context.layers[self.kaddr_space].config["kernel_virtual_offset"]
        self.ntkrnlmp = self._context.module(self.config['nt_symbols'],
                                        layer_name=self.kaddr_space,
                                        offset=self.kvo)
        self.kdbg = info.Info.get_kdbg_structure(self.context, self.config_path, self.kaddr_space, self.config['nt_symbols'])

        self.get_pfn_info = PFNInfo(self.context.clone(), self.config_path)
        self.get_pfn_info_clone = PFNInfo(self.context.clone(), self.config_path)
        self.physical_to_virtual = P2V(self.context.clone(), self.config_path)#PtoV(context, self.config_path)
        self.PageListSummary = {}
        self.FileSummary = {}
        self.PageSummary = []

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.StringRequirement(name='ADDRESS',
                                             description='Address to translate',
                                             optional=True),
                requirements.StringRequirement(name='SIZE',
                                               description='Length to translate',
                                               optional=True),
                requirements.BooleanRequirement(name='COLORED',
                                                description='Parse every directory under the root dir',
                                                optional=True),

                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
                ]

    def file_exp_builder(self, c_dict, path_list, data):

        if len(path_list) > 0:
            value = path_list.pop(0)
            if value in c_dict:
                self.file_exp_builder(c_dict[value], path_list, data)
            else:
                c_dict[value] = {}
                self.file_exp_builder(c_dict[value], path_list, data)
        else:
            # For the filesummary: view all the pages inside the file.
            if "|properties|" in c_dict:
                c_dict["|properties|"] = (data[0], c_dict["|properties|"][1] + 0x1000)
            else:
                c_dict["|properties|"] = data

    def xrange_big(self, start, end, step):
        while start < end:
            yield start
            start += step

    def _generator(self):
        start_range = self._config.ADDRESS + 0x100000 if 0x100000 < self._config.SIZE else self._config.SIZE
        self.add_data(self._config.ADDRESS, start_range)

    def add_data(self, start, end, page_size=0x1000):
        failed_count = 0
        for addr in self.xrange_big(start, end, page_size):
            #print(addr)
            va, owner, file_name, file_offset, additional_info = self.physical_to_virtual.ptov(addr)#self.physical_to_virtual.ptov(addr)
            if va == 'Invalid pfn, Translation failed..':
                self.PageSummary.append((hex(addr), '', 'Invalid / Unused / Hardware /', '', '', '', '', '', '', '',''))
                continue
            in_vad = ''
            if type(owner) is list:
                for e_proc_index in range(len(owner)):
                    p = owner[e_proc_index]
                    c_va = va[e_proc_index]
                    if int(p.UniqueProcessId) in self.physical_to_virtual.vads:
                        for start_range, end_range, c_vad in self.physical_to_virtual.vads[int(p.UniqueProcessId)]:
                            if c_va > start_range and c_va < end_range:
                                in_vad += ', {}'.format(c_vad.get_protection(vadinfo.VadInfo.protect_values(self.context, self.kaddr_space, self.config['nt_symbols']),vadinfo.winnt_protections))
                                break
                        else:
                            in_vad += ', False'
                    else:
                        in_vad += ', False'
                in_vad = in_vad[2:]
                pids = [str(int(p.UniqueProcessId)) for p in owner]
            elif owner:
                pids = [objects.utility.array_to_string(owner.ImageFileName), owner.UniqueProcessId]
                if int(owner.UniqueProcessId) in self.physical_to_virtual.vads:
                    for start_range, end_range, c_vad in self.physical_to_virtual.vads[int(owner.UniqueProcessId)]:
                        if va > start_range and va < end_range:
                            in_vad = c_vad.get_protection(vadinfo.VadInfo.protect_values(self.context, self.kaddr_space, self.config['nt_symbols']),vadinfo.winnt_protections)
                            break
                    else:
                        in_vad = 'False'
                else:
                    in_vad = 'False'
            else:
                pids = ''

            pfn_addr = self.get_pfn_info.get_physical_from_index(addr >> 12)

            if type(va) is list and len(va) > 0 :
                pfn_info = self.get_pfn_info.pfn_info(pfn_addr, va=max(va), pool=False)
                va = [hex(v) for v in va]
            else:
                pfn_info = self.get_pfn_info.pfn_info(pfn_addr, va=va, pool=False)
                va = hex(va)

            failed_count = 0
            (page_list, priority, reference, share_count, page_color, pte_type, protection, use, file_name, offset, image, pool_tag_list) = pfn_info
            if type(file_name) != renderers.UnreadableValue and file_name and file_name != 'None' and file_name != 'File Name address invalid (maybe paged out)':
                file_type = file_name.split('.')
                data = (file_type[-1] if len(file_type) > 1 else '', 0x1000)
                self.file_exp_builder(self.FileSummary, file_name[1:].split('\\'), data)

            data = (hex(addr), page_list, use, priority, image, hex(offset)  or '', file_name or '',pids, va, protection, in_vad)

            self.PageSummary.append(data)

    def run(self):
        self.render_ui(self._generator())

    def render_ui(self, data):
        global app
        global file_path
        pages_dict = {'MmBadPagesDetected':self.kdbg.MmBadPagesDetected,
        'MmModifiedPageListHead':self.kdbg.MmModifiedPageListHead,
        'MmResidentAvailablePages':self.kdbg.MmResidentAvailablePages,
        'MmFreePageListHead':self.kdbg.MmFreePageListHead,
        'MmStandbyPageListHead': self.kdbg.MmStandbyPageListHead,
        'MmModifiedNoWritePageListHead': self.kdbg.MmModifiedNoWritePageListHead,
        'MmZeroedPageListHead':self.kdbg.MmZeroedPageListHead}
        for page_list in pages_dict:
            try:
                pfnlist = self.ntkrnlmp.object('_MMPFNLIST', pages_dict[page_list] - self.kvo)
                self.PageListSummary[page_list] = int(pfnlist.Total)
            except exceptions.InvalidAddressException:
                self.PageListSummary[page_list] = "-"

        file_path = urllib.request.url2pathname(self.context.config['automagic.LayerStacker.single_location'][file_slice:])
        app = MemoryInformation(self.PageListSummary, self.PageSummary, self.FileSummary, self.get_pfn_info_clone)
        app.title("Memory Information")
        app.geometry("700x450")
        app.tk.call('tk', 'scaling', 1.4)
        self.style = s = ThemedStyle(app) if has_themes else tkinter.ttk.Style()
        s.layout("Tab",[('Notebook.tab', {'sticky': 'nswe', 'children':
            [('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children':
                [('Notebook.label', {'side': 'top', 'sticky': ''})],
                                   })],
                                          })])
        def fixed_map(option):
            # Returns the style map for 'option' with any styles starting with
            # ("!disabled", "!selected", ...) filtered out

            # style.map() returns an empty list for missing options, so this should
            # be future-safe
            return [elm for elm in s.map("Treeview", query_opt=option)
                    if elm[:2] != ("!disabled", "!selected")]
        s.map("Treeview",
                  foreground=fixed_map("foreground"),
                  background=fixed_map("background"))

        def on_exit(none=None):
            '''
            Exit popup
            :param none: None (support event)
            :return: None
            '''
            if messagebox.askokcancel("Quit",
                                      "Do you really wish to quit?"):
                app.destroy()
                os._exit(1)
                sys.exit()
        app.protocol("WM_DELETE_WINDOW", on_exit)

        threading.Thread(target=self.add_data, args=(self._config.ADDRESS+0x100000, self._config.ADDRESS+0x100000 + self._config.SIZE)).start()

        def insert_fast(self, data, index_start, index_end, color):
            for index_item in range(index_start, index_end):
                item = data[index_item]
                self.data.append(item)
                #try:
                # Mark all executable pages that marked in vad as non executed, Exclude system (its not really use vad).
                if item[-2]!='' and (not int(item[-2])) and ('EXECUTE' not in item[-1] and item[-1] != 'False' ) and item[7] != ['System', 4]:
                    c_tag = ('vad_conflict',)
                # Mark all non files executable pages.
                elif item[-2]!='' and ( not int(item[-2])) and item[2] != 'Mapped File':
                    c_tag = ('no_file_execute',)
                # Mark all executable pages that mark dont presend in the vad (exclude system as well)
                elif item[-2]!='' and ( not int(item[-2])) and 'EXECUTE' not in item[-1] and item[7] != ['System', 4]:
                    c_tag = ('execute_no_vad',)
                # Mark all non execute pages that presend in vad as execute (page protection changes..)
                elif item[-2]!='' and int(item[-2]) and 'EXECUTE' in item[-1] and (any (iii != "PAGE_EXECUTE_WRITECOPY" for iii in item[-1].split(', '))  or item[4] != True):
                    c_tag = ('ntbit_conflict',)
                # To insert onlly COLORED pages.
                elif color:
                    continue
                else:
                    c_tag = item[self.text_by_item]

                self.tree.insert('', END, values=item, text=item[self.text_by_item], tags=c_tag)
                    #self.visual_drag.insert('', END, values=item, text=item[self.text_by_item], tags=item[self.text_by_item])
                #except (Exception, tk.TclError):
                #	print('failed to insert {} to the table'.format(item[self.text_by_item]))

        # Insert init items, and set default color
        app.frames['PhysicalRanges'].tree.insert_fast = insert_fast
        app.frames['PhysicalRanges'].tree.tree.tag_configure('vad_conflict', background='red')
        app.frames['PhysicalRanges'].tree.tree.tag_configure('no_file_execute', background='orange')
        app.frames['PhysicalRanges'].tree.tree.tag_configure('execute_no_vad', background='yellow')
        app.frames['PhysicalRanges'].tree.tree.tag_configure('ntbit_conflict', background='purple')
        last_inserted = to_insert_index = 0
        while True:
            app.update()
            app.update_idletasks()
            time.sleep(0.01)
            to_insert_index = len(self.PageSummary)# if to_insert_index - last_inserted < 25 else last_inserted+25
            app.frames['PhysicalRanges'].tree.insert_fast(app.frames['PhysicalRanges'].tree, self.PageSummary, last_inserted,to_insert_index, self._config.COLORED)
            last_inserted = to_insert_index
        app.destroy()
        os._exit(1)
        sys.exit()

#region sc Start
# Help volatility users Do not use this classes..
class p2v(P2V):
    pass

class pfninfo(PFNInfo):
    pass

class rammap(RamMap):
    pass
#endregion sc End
