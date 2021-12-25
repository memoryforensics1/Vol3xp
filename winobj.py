# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Creator: Aviel Zohar (memoryforensicsanalysis@gmail.com)
import logging
from typing import List

from volatility3.framework import renderers, interfaces, objects, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
import volatility3.plugins.windows.info as info
import volatility3.plugins.windows.handles as handles
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

#Globals
NAME                            = 0x1
ADDR                            = 0x0
HEADER                          = 0x2
VALUES                          = 0x1
ADDITIONAL_INFO                 = 0x3


class WinObj(interfaces.plugins.PluginInterface):
	"""
	 Object Manager Enumeration
	"""

	_required_framework_version = (2, 0, 0)
	_version = (2, 0, 0)

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		self.config['primary'] = self.context.modules[self.config['kernel']].layer_name
		self.config['nt_symbols'] = self.context.modules[self.config['kernel']].symbol_table_name
		self.kaddr_space = self.config['primary']
		self.kvo = self.context.layers[self.config['primary']].config["kernel_virtual_offset"]
		self.ntkrnlmp = self._context.module(self.config['nt_symbols'],
		                                     layer_name=self.kaddr_space,
		                                     offset=self.kvo)

		# Get the cookie (or none if this version dont use cookie).
		try:
			offset = self.context.symbol_space.get_symbol(self.config["nt_symbols"] + constants.BANG + "ObHeaderCookie").address
			kvo = self.context.layers[self.config["primary"]].config['kernel_virtual_offset']
			self.cookie = self.context.object(self.config["nt_symbols"] + constants.BANG + "unsigned int" , self.config["primary"], offset=kvo + offset)
		except exceptions.SymbolError:
			self.cookie = None

		self._protect_values = None
		self.root_obj_list = []
		self.tables = {}
		self.exlude_types = []

		# Sets default values of a 64 bit machine,
		#the values will be updated according to the profile
		self.POINTER_SIZE                    = 0x8
		self.OBJECT_HEADER_QUOTA_INFO_SIZE   = 0x20
		self.OBJECT_HEADER_PROCESS_INFO_SIZE = 0x10
		self.OBJECT_HEADER_HANDLE_INFO_SIZE  = 0x10
		self.OBJECT_HEADER_NAME_INFO_SIZE    = 0x20
		self.OBJECT_HEADER_CREATOR_INFO_SIZE = 0x20
		self.OBJECT_HEADER_NAME_INFO_ID      = 0x2
		self.OBJECT_HEADER_CREATOR_INFO_ID   = 0x1
		self.OBJECT_HEADER_HANDLE_INFO_ID    = 0x4
		self.OBJECT_HEADER_QUOTA_INFO_ID     = 0x8
		self.OBJECT_HEADER_PROCESS_INFO_ID   = 0x10
		self.OBJECT_HEADER_SIZE              = 0x30
		self.OBJECT_POOL_HEADER              = 0x10
		self.OBJECT_INFO_HEADERS_LIST        = [self.OBJECT_HEADER_CREATOR_INFO_ID,
												 self.OBJECT_HEADER_HANDLE_INFO_ID,
												 self.OBJECT_HEADER_QUOTA_INFO_ID,
												 self.OBJECT_HEADER_NAME_INFO_ID,
												 self.OBJECT_HEADER_PROCESS_INFO_ID]

		self.OBJECT_INFO_HEADERS_ID_TO_SIZE  ={self.OBJECT_HEADER_NAME_INFO_ID: self.OBJECT_HEADER_NAME_INFO_SIZE,
											   self.OBJECT_HEADER_CREATOR_INFO_ID: self.OBJECT_HEADER_CREATOR_INFO_SIZE,
											   self.OBJECT_HEADER_HANDLE_INFO_ID : self.OBJECT_HEADER_HANDLE_INFO_SIZE,
											   self.OBJECT_HEADER_QUOTA_INFO_ID : self.OBJECT_HEADER_QUOTA_INFO_SIZE,
											   self.OBJECT_HEADER_PROCESS_INFO_ID: self.OBJECT_HEADER_PROCESS_INFO_SIZE}
		self.type_map = handles.Handles.get_type_map(self.context,  self.config["primary"], self.config["nt_symbols"])

	@classmethod
	def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
		# Since we're calling the plugin, make sure we have the plugin's requirements
		return [requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
				requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
				requirements.BooleanRequirement(name='PARSE_ALL',
											 description='Parse every directory under the root dir',
											 optional=True),
				requirements.StringRequirement(name='SUPPLY_ADDR',
											 description='Parse directories under specific addresses',
											 optional=True),
				requirements.StringRequirement(name='FULL_PATH',
											 description='Parse a directory found by full path location',
											 optional=True),
				]

	def get_root_directory(self):
		"""
		:return          : a pointer to the root directory
		"""
		# gets the pointer
		# if for some reason ObpRootDirectoryObject not exist lets take the value from ObpRootDirectoryObject
		try:
			import struct
			_pointer_struct = struct.Struct("<Q") if self.ntkrnlmp.get_type('pointer').size == 8 else struct.Struct('I')
			root_dir_addr = int(_pointer_struct.unpack(
				self.context.layers['primary'].read(self.ntkrnlmp.get_symbol('ObpRootDirectoryObject').address + self.ntkrnlmp.offset, self.ntkrnlmp.get_type('pointer').size))[0])
		except:
			root_dir_addr = info.Info.get_kdbg_structure(self.context, self.config_path, self.config['primary'], self.config['nt_symbols']).ObpRootDirectoryObject
			root_dir_addr = self.ntkrnlmp.object("pointer", offset=root_dir_addr - self.ntkrnlmp.offset)
		return root_dir_addr

	def update_sizes(self):
		"""
		:return          : None
		the function will update the sizes of the vtype objects according to their sizes from the selected profile
		"""
		# updates pointer size
		self.POINTER_SIZE = self.ntkrnlmp.get_type("pointer").size

		# checks if the profile has the structure
		try:
			self.OBJECT_HEADER_QUOTA_INFO_SIZE   = self.ntkrnlmp.get_type("_OBJECT_HEADER_QUOTA_INFO").size
		except:
			self.OBJECT_HEADER_QUOTA_INFO_SIZE = 0x0

		# checks if the profile has the structure
		try:
			self.OBJECT_HEADER_PROCESS_INFO_SIZE = self.ntkrnlmp.get_type("_OBJECT_HEADER_PROCESS_INFO").size
		except:
			self.OBJECT_HEADER_PROCESS_INFO_SIZE = 0x0

		# checks if the profile has the structure
		try:
			self.OBJECT_HEADER_HANDLE_INFO_SIZE  = self.ntkrnlmp.get_type("_OBJECT_HEADER_HANDLE_INFO").size
		except:
			self.OBJECT_HEADER_HANDLE_INFO_SIZE  = 0

		# checks if the profile has the structure
		try:
			self.OBJECT_HEADER_CREATOR_INFO_SIZE = self.ntkrnlmp.get_type("_OBJECT_HEADER_CREATOR_INFO").size
		except:
			self.OBJECT_HEADER_CREATOR_INFO_SIZE = 0x0

		self.OBJECT_HEADER_NAME_INFO_SIZE    = self.ntkrnlmp.get_type("_OBJECT_HEADER_NAME_INFO").size

		# subtract 0x8 from the size to remove the body itself (the last member of the _object_header)
		self.OBJECT_HEADER_SIZE              = self.ntkrnlmp.get_type('_OBJECT_HEADER').relative_child_offset('Body')

	def get_all_object_headers(self, mask):
		"""
		:param mask: InfoMask from the object header
		:return    : list
		the function will return all the info headers that present in the object
		"""
		present_info_headers = []

		for info_id in self.OBJECT_INFO_HEADERS_LIST:

			# checks if the header presents
			if mask & info_id != 0:
				present_info_headers.append(info_id)

		return present_info_headers

	def get_additional_info(self, myObj, obj_type, obj_header):
		"""
		:param myObj     : pointer object
		:param obj_type  : string of the type
		:param obj_header: "_OBJECT_HEADER"
		:return          : list
		the function will return additional information about the object
		"""
		layer_name = self.config['primary']
		kvo = self.context.layers[layer_name].config["kernel_virtual_offset"]
		# additional information about SymbolicLink
		if obj_type == "SymbolicLink":
			myObj = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
				'_OBJECT_SYMBOLIC_LINK')
			return "Target: {}".format(myObj.LinkTarget.get_string())

		# additional information about Section
		elif obj_type == "Section" and self.ntkrnlmp.has_type("_OBJECT_HEADER"):
			try:
				if self.ntkrnlmp.has_type('_SECTION_OBJECT'):
					myObj = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
						'_SECTION_OBJECT').Segment.dereference().cast("_SEGMENT").ControlArea
				else:
					# Windows 10 rename _SECTION_OBJECT -> _SECTION
					myObj = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast(
						"_EX_FAST_REF").dereference().cast('_SECTION').u1.ControlArea
			except:
				return "(parse object failed on address: {}".format(myObj)
			# the default is "_SEGMENT_OBJECT", and we need _SEGMENT
			try:
				fileName = myObj.FilePointer.dereference().cast("_FILE_OBJECT").file_name_with_device()
			except:
				return "(parse file name failed on address: {}".format(myObj)

			return "FileObj: {}".format(fileName)

		# additional information about Driver
		elif obj_type == "Driver":
			driver = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
				'_DRIVER_OBJECT')
			try:
				return "Full Name: {}".format(driver.DriverName.String)
			except:
				return "(parse name failed on address: {}".format(driver)

		# additional information about Device
		elif obj_type == "Device":
			device = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
				'_DEVICE_OBJECT')
			try:
				return "Driver: {}".format(device.DriverObject.DriverName.String)
			except:
				return "(parse name failed on address: {}".format(device)

		# additional information about Type
		elif obj_type == "Type":
			myType = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
				'_OBJECT_TYPE')
			key = self.ntkrnlmp.object("string", offset=myType.Key.vol.offset - kvo, max_length=4, errors="replace")
			return "Key: {}".format(key)

		# additional information about Window Station (Not supported yet..)
		elif obj_type == "WindowStation" and False:
			win_sta = self.ntkrnlmp.object("pointer", offset=myObj.vol.offset - kvo).cast("_EX_FAST_REF").dereference().cast(
				'tagWINDOWSTATION')
			names = "".join("{} ".format(Desktop.Name) for Desktop in win_sta.desktops()).strip()
			session_id = win_sta.dwSessionId
			atom_table = hex(win_sta.pGlobalAtomTable)[:-1]
			return "Desktop Names:{},Session Id:{},Atoms:{}".format(names,session_id,atom_table)

		# additional information about all the others
		else:
			return "Handle Count - {}, Pointer Count {}".format(obj_header.HandleCount,obj_header.PointerCount)

	def GetName(self, obj_header):
		"""
		:param obj_header: "_OBJECT_HEADER"
		:return          : string
		the function will return the name of the object
		"""

		# When this work in volatility for all version just replace the function with this
		#try:
		#	name_info = obj_header.NameInfo()
		#	return name_info.Name.get_string()
		#except:
		#	return ''

		# checks if this is an old version
		if self.ntkrnlmp.get_type("_OBJECT_HEADER").has_member('NameInfoOffset'):
			size = obj_header.NameInfoOffset

		# new version
		else:
			try:
				info_headers = self.get_all_object_headers(obj_header.InfoMask)
			except:
				return ""

			# calculates the size according to the info headers
			if self.OBJECT_HEADER_CREATOR_INFO_ID in info_headers:
				size = self.OBJECT_HEADER_NAME_INFO_SIZE + self.OBJECT_HEADER_CREATOR_INFO_SIZE
			else:
				size = self.OBJECT_HEADER_NAME_INFO_SIZE

		layer_name = self.config['primary']
		kvo = self.context.layers[layer_name].config["kernel_virtual_offset"]
		name_info = self.ntkrnlmp.object("_OBJECT_HEADER_NAME_INFO", offset=obj_header.vol.offset - kvo - size)

		# checks that the name is not empty
		if name_info.Name:
			# validates the name
			#if name_info.Name.Buffer and name_info.Name.Length <= name_info.Name.MaximumLength:
			try:
				return name_info.Name.get_string()
			except:
				return ""
		return ""

	def AddToList(self, myObj, l):
		"""
		:param myObj     : pointer object
		:param l         : list
		:return          : None
		the function will add the object to the received list after a validation
		"""
		layer_name = self.config['primary']
		kvo = self.context.layers[layer_name].config["kernel_virtual_offset"]
		obj_header = self.ntkrnlmp.object("_OBJECT_HEADER", offset=myObj.cast('pointer').real - self.OBJECT_HEADER_SIZE - kvo)

		# Make sure that there is no duplicated, and validate the pointer.
		for item in l:
			try:
				if item[0] == myObj:
					return
				elif (not obj_header.is_valid()) or (obj_header.PointerCount < 1 and obj_header.HandleCount < 1) or \
						(obj_header.PointerCount < 0 or obj_header.HandleCount < 0):
					return
			except:
				return
		name = self.GetName(obj_header)
		# validates the object
		if name:
			obj_type = obj_header.get_object_type(self.type_map, self.cookie)
			if obj_type in self.exlude_types:
				return
			add_info = self.get_additional_info(myObj, obj_type, obj_header)
			l.append((myObj,name,obj_header,add_info))

	def parse_directory(self, addr, l):
		"""
		:param addr      : long, pointer the the driectory
		:param l         : list
		:return          : None
		the function will parse the directory and add every valid object to the received list
		"""
		seen = set()
		layer_name = self.config['primary']
		kvo = self.context.layers[layer_name].config["kernel_virtual_offset"]
		directory_array = self.ntkrnlmp.object('_OBJECT_DIRECTORY', addr - self.ntkrnlmp.offset)
		for pointer_addr in directory_array.HashBuckets:
			if not pointer_addr or pointer_addr == 0xffffffff:
				continue

			# Walk the ChainLink foreach item inside the directory.
			while pointer_addr not in seen:
				try:
					myObj = self.ntkrnlmp.object("pointer", offset=pointer_addr+self.POINTER_SIZE - kvo)
					self.AddToList(myObj, l)
				except exceptions.InvalidAddressException:
					pass

				seen.add(pointer_addr)
				try:
					pointer_addr = pointer_addr.ChainLink
				except exceptions.InvalidAddressException:
					break
				if not pointer_addr:
					break

	def get_directory(self, name="", root_dir=[]):
		"""
		:param name      : string
		:param root_dir  : list of tuples
		:return          : None
		the function will parse the root directory object and add every directory/given name,
		to the tables dictionary
		"""
		l = []
		name = str(name)

		# checks whether a root dir was given or not
		if not root_dir:

			# default option
			root_dir = self.root_obj_list

		# parses the root directory
		for obj,obj_name,obj_header,add_info in root_dir:
			# if there is a specific name
			if name:
				# if this is the name that was received
				if name.lower() == obj_name.lower():
					self.parse_directory(obj, l)
					self.tables[obj_name] = (obj.vol.offset, l)
					break

			# parse all
			else:
				# checks if object is a directory
				if obj_header.get_object_type(self.type_map) == "Directory":
					self.parse_directory(obj, l)
					self.tables[obj_name] = (obj.vol.offset,l)
					l = []

	def SaveByPath(self, path):
		"""
		This function get a path to directory append all the data in this directory to self.tables
		:param path: path in the object directory to get all the object information from.
		:return:
		"""
		# validation
		try:

			# takes a copy in order to remove all stages from the final parser
			save = self.tables.copy()

			stages = path.split("/")[1:]

			# allow backslashes as well
			if len(stages) == 0:
				stages = path.split("\\")[1:]

			self.get_directory(stages[0])


			addr,current_dir = self.tables[stages[0]]


			for place,stage in enumerate(stages[1:]):
				self.get_directory(stage,current_dir)
				addr,current_dir = self.tables[stage]

			# removes all stages
			save_list = current_dir
			self.tables = save

			#sets the full path in the dictionary
			self.tables[path] = (addr,current_dir)

		except KeyError:
			raise KeyError("Invalid Path -> {}".format(path))

	def get_object_information(self):
		"""
		Check user parameters and start to get the information
		:return: None
		"""
		# updates objects size
		self.update_sizes()

		# Get root directory
		root_dir = self.get_root_directory()
		self.parse_directory(root_dir, self.root_obj_list)

		# checks for the SUPPLY_ADDR option
		if self.config.get('SUPPLY_ADDR', None):
			addrs = self.config.get('SUPPLY_ADDR', None).split(",")
			for addr in addrs:
				l = []

				# validates the address
				try:
					addr = eval(addr)

				# addr is not valid
				except (SyntaxError,NameError):
					continue

				obj_header = self.ntkrnlmp.object("_OBJECT_HEADER", offset=addr-self.OBJECT_HEADER_SIZE - self.ntkrnlmp.offset)
				name = self.GetName(obj_header)

				# validates the directory
				if name:
					self.parse_directory(addr, l)
					self.tables[name] = (addr, l)

		# checks for the FULL_PATH option
		elif self.config.get('FULL_PATH', None):

			# gets all dirs
			dirs = self.config.get('FULL_PATH', None).split(",")
			for path in dirs:
				self.SaveByPath(path)

		# default option
		else:
			self.tables["/"] = (root_dir,self.root_obj_list)

			# checks for the PARSE_ALL option
			if self.config.get('PARSE_ALL', None):
				self.get_directory()

	def _generator(self):
		self.get_object_information()
		for table in self.tables:
			l = self.tables[table][VALUES]
			for obj in l:
				yield (0,[hex(obj[ADDR]), str(obj[NAME]), str(obj[HEADER].get_object_type(self.type_map)), str(obj[ADDITIONAL_INFO])])

	def run(self):
		return renderers.TreeGrid([("Object Address(V)", str), ("Name", str), ("str", str), ("Additional Info", str)],
								  self._generator())
