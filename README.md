# funkbuster-ida-plugin
IDA plugin for analyzing, filtering and tracing functions and call flows

## Installation
#### 1. Install Python
- Download and install Python 3.x from the [official website](https://www.python.org/).
- Ensure to add Python to your `PATH` during the installation.
#### 2. Configure IDA to use Python
#### 3. Instal PyQt5
Install PyQt5 using pip for GUI functionality in plugins:
```bash
pip install PyQt5
```
Note: Installing PyQt5 might require you to have Microsoft Visual C++ 14.0 or greater and the Windows SDK installed on your system.

_Developed and tested under IDA Pro 7.7 and Python 3.11.0_

## User Interface Overview
![funkbuster-ida-plugin-UI](https://github.com/ep1h/funkbuster-ida-plugin/assets/46194184/89483e05-d5f8-4810-a1db-7f5b56fbd581)

The plugin's User Interface is composed of three major sections: **Filters**, **Results**, and **Info**, designed to facilitate a seamless and efficient function analysis and navigation experience within IDA.

### 1. Filters Section

This section allows users to configure filters, enabling the search for functions based on various parameters.

#### 1.1 Visible Sections
Toggle the display of filter setting windows. Note that hiding a section does *not* deactivate its filters.

#### 1.2 Signatures
Specify required or prohibited signatures in functions. Utilize the "Inverted" checkbox to toggle between the necessity and prohibition of signatures, while the "Enabled" checkbox activates or deactivates the filter. Manage signatures easily with right-click options.

#### 1.3 Cross-References (Xrefs)
Define address references necessary for function filtering. Set the directionality and type of cross-references (to/from an address and read/write/access, respectively) using the provided checkboxes. Cross-reference filters are easily managed and inverted with a right-click menu.

#### 1.4 Flows
The Flows section enables users to stipulate address prerequisites that must be navigable from or to the function to pass the filter. Two essential parameters guide this feature:

- **Direction**: Dictates the permissible navigation direction between the function and specified addresses. It can be set to ensure that the function can reach the address, be reached from the address, or both.

- **Depth**: Indicates the maximum call depth allowed for reaching from one function to another. If a function can reach another through a chain of calls but exceeds the specified depth, it will be filtered out.

Flows can be utilized to identify potential execution paths or to highlight complex call hierarchies within the analyzed binary. Manage and invert flow filters with the familiar right-click context menu.

Just like other sections, the Flows filtering rules can be temporarily disabled or inverted by utilizing the "Enabled" and "Inverted" checkboxes, respectively. Users can also delete a flow filter by selecting it, right-clicking, and choosing "Delete" from the context menu.
#### 1.5 Analysis
Initiate an analysis with the "Analyze" button, applying configured filters and displaying compliant functions in the "Results" section. Optionally apply filters only to currently displayed results with the "Analyze only current results" checkbox.

### 2. Results Section

The "Results" section displays filtered functions or all functions if no filters are defined. Navigate directly to functions within IDA with a double click, or view detailed information in the "Info" section with a single click. Undo previous filter applications with the "Undo Previous Analysis" button.

### 3. Info Section

This section presents detailed information about the selected function, including general details, Xrefs, and potential virtual function calls.

#### 3.1 General Information
Displays the address, name, and size of the selected function.

#### 3.2 Xrefs From
Showcases data accessed from, and functions called from, the selected function. Navigate to the current Xref To or the Xref itself by double-clicking the "Offset" and "Address" columns, respectively. Specify which Xrefs to display via configurable options.

#### 3.3 Xrefs To
This subsection parallels the functionality of Xrefs From but focuses on external references *to* the current function. Navigate and manage Xrefs with double clicks and context menu options.

#### 3.4 Potential VMT Calls
Displays potential virtual function calls, presenting call addresses, VMT offsets, and instructions in respective columns.

All elements (addresses, offsets, names) in the plugin UI are interactive, facilitating easy navigation to relevant IDA code through double-click actions.
