### 2025/10/20 - v2.0#beta.02
* Updated the acknowledgements list.

* Added `tamper/urlencode.py` script.

* Fixed some `DebugLevel()` function errors left from older versions:

  * `configs/setting_data.py`

  * `lib/utils/my_functions.py`

* Modularized the payload modification workflow.

* Fixed incorrect display of payload prompts.

* Fixed payloads that failed to target the specified backend technology correctly.

* Fixed an issue where selecting a non-PHP backend still caused PHP wrapper tests and produced an uninitialized `--php-wrapper` parameter prompt.



### 2025/10/01 - v2.0#beta.01
* Refactored most of the codebase and architecture; removed or fixed verbose/inefficient patterns.

* Fixed incorrect prompt display during some testing.

* Fixed XSS where the current parameter marked with * was tested twice.

* Fixed duplicate prompt display for the current parameter marked with *.

* Fixed issues with correctly specifying backend technology and backend OS.

* Added test payloads: JSP → web.xml, ASPX → web.config.

* Optimize parameter display