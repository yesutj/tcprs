# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.2

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yesutj/tcprs

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yesutj/tcprs/build

# Utility rule file for bif-init-yesutj_TCPRS.

# Include the progress variables for this target.
include CMakeFiles/bif-init-yesutj_TCPRS.dir/progress.make

CMakeFiles/bif-init-yesutj_TCPRS:
	cd /home/yesutj/tcprs/build/lib/bif && sh -c "rm -f /home/yesutj/tcprs/build/lib/bif/__load__.zeek"
	cd /home/yesutj/tcprs/build/lib/bif && sh -c "for i in  tcprs.bif.zeek tcprs_const.bif.zeek; do echo @load ./\$$i >> /home/yesutj/tcprs/build/lib/bif/__load__.zeek; done"

bif-init-yesutj_TCPRS: CMakeFiles/bif-init-yesutj_TCPRS
bif-init-yesutj_TCPRS: CMakeFiles/bif-init-yesutj_TCPRS.dir/build.make
.PHONY : bif-init-yesutj_TCPRS

# Rule to build all files generated by this target.
CMakeFiles/bif-init-yesutj_TCPRS.dir/build: bif-init-yesutj_TCPRS
.PHONY : CMakeFiles/bif-init-yesutj_TCPRS.dir/build

CMakeFiles/bif-init-yesutj_TCPRS.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bif-init-yesutj_TCPRS.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bif-init-yesutj_TCPRS.dir/clean

CMakeFiles/bif-init-yesutj_TCPRS.dir/depend:
	cd /home/yesutj/tcprs/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yesutj/tcprs /home/yesutj/tcprs /home/yesutj/tcprs/build /home/yesutj/tcprs/build /home/yesutj/tcprs/build/CMakeFiles/bif-init-yesutj_TCPRS.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bif-init-yesutj_TCPRS.dir/depend
