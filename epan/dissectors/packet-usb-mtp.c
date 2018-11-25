#include "config.h"
#include <stdio.h>
#include "packet-usb.h"
#include <epan/address_types.h>
#include <epan/proto_data.h>

static int proto_mtp = -1;

static int hf_container_length = -1;
static int hf_container_type = -1;
static int hf_operation_code = -1;
static int hf_response_code = -1;
static int hf_event_code = -1;
static int hf_transaction_id = -1;
static int hf_session_id = -1;
static int hf_object_prop_code = -1;
static int hf_object_format_code = -1;
static int hf_storage_id = -1;
static int hf_object_handle = -1;
static int hf_device_prop_code = -1;
static int hf_offset = -1;
static int hf_max_n_bytes = -1;
static int hf_protection_status = -1;
static int hf_object_prop_group_code = -1;
static int hf_skip_index = -1;
static int hf_depth = -1;
static int hf_self_test_type = -1;
static int hf_file_system_format = -1;
static int hf_standard_version = -1;
static int hf_vendor_extension_id = -1;
static int hf_mtp_version = -1;
static int hf_functional_mode = -1;
static int hf_mtp_extensions = -1;
static int hf_manufacturer = -1;
static int hf_model = -1;
static int hf_device_version = -1;
static int hf_serial_number = -1;
static int hf_datatype = -1;
static int hf_storage_type = -1;
static int hf_factory_default_value = -1;
static int hf_get_set = -1;
static int hf_default_value = -1;
static int hf_group_code = -1;
static int hf_access_capability = -1;
static int hf_max_capacity = -1;
static int hf_free_space = -1;
static int hf_free_space_objects = -1;
static int hf_storage_description = -1;
static int hf_volume_identifier = -1;
static int hf_form_flag = -1;
static int hf_maximum_value = -1;
static int hf_minimum_value = -1;
static int hf_step_size = -1;
static int hf_number_of_values = -1;
static int hf_supported_value = -1;
static int hf_date_time = -1;
static int hf_length = -1;
static int hf_regexp = -1;
static int hf_max_length = -1;
static int hf_object_compressed_size = -1;
static int hf_thumb_format = -1;
static int hf_thumb_compressed_size = -1;
static int hf_thumb_pix_width = -1;
static int hf_thumb_pix_height = -1;
static int hf_image_pix_width = -1;
static int hf_image_pix_height = -1;
static int hf_parent_object = -1;
static int hf_association_type = -1;
static int hf_association_desc = -1;
static int hf_sequence_number = -1;
static int hf_filename = -1;
static int hf_date_created = -1;
static int hf_date_modified = -1;
static int hf_keywords = -1;
static int hf_image_bit_depth = -1;
static int hf_current_value = -1;
static int hf_number_of_elements = -1;
static int hf_value = -1;
static int hf_value_str = -1;
static int hf_object_binary_data = -1;
static int hf_thumbnail_data = -1;
static int hf_device_prop_value = -1;
static int hf_object_prop_value = -1;
static int hf_num_objects = -1;
static int hf_bytes_sent = -1;
static int hf_failed_property = -1;
static int hf_n_interdependencies = -1;
static int hf_n_prop_descs = -1;

static gint ett_mtp_array = -1;
static gint ett_mtp = -1;
static gint ett_mtp_parameters = -1;
static gint ett_mtp_dev_info = -1;
static gint ett_mtp_prop_desc = -1;
static gint ett_mtp_storage_info = -1;
static gint ett_mtp_object_info = -1;
static gint ett_mtp_dev_prop_desc = -1;
static gint ett_mtp_object_prop_list = -1;
static gint ett_element = -1;

#define MTP_TYPE_CMD        0x1
#define MTP_TYPE_DATA       0x2
#define MTP_TYPE_RESPONSE   0x3
#define MTP_TYPE_EVENT      0x4

#define MTP_GET_DEVICE_INFO               0x1001
#define MTP_OPEN_SESSION                  0x1002
#define MTP_CLOSE_SESSION                 0x1003
#define MTP_GET_STORAGE_IDS               0x1004
#define MTP_GET_STORAGE_INFO              0x1005
#define MTP_GET_NUM_OBJECTS               0x1006
#define MTP_GET_OBJECT_HANDLES            0x1007
#define MTP_GET_OBJECT_INFO               0x1008
#define MTP_GET_OBJECT                    0x1009
#define MTP_GET_THUMB                     0x100A
#define MTP_DELETE_OBJECT                 0x100B
#define MTP_SEND_OBJECT_INFO              0x100C
#define MTP_SEND_OBJECT                   0x100D
#define MTP_INITIATE_CAPTURE              0x100E
#define MTP_FORMAT_STORE                  0x100F
#define MTP_RESET_DEVICE                  0x1010
#define MTP_SELF_TEST                     0x1011
#define MTP_SET_OBJECT_PROTECTION         0x1012
#define MTP_POWER_DOWN                    0x1013
#define MTP_GET_DEVICE_PROP_DESC          0x1014
#define MTP_GET_DEVICE_PROP_VALUE         0x1015
#define MTP_SET_DEVICE_PROP_VALUE         0x1016
#define MTP_RESET_DEVICE_PROP_VALUE       0x1017
#define MTP_TERMINATE_OPEN_CAPTURE        0x1018
#define MTP_MOVE_OBJECT                   0x1019
#define MTP_COPY_OBJECT                   0x101A
#define MTP_GET_PARTIAL_OBJECT            0x101B
#define MTP_INITIATE_OPEN_CAPTURE         0x101C
#define MTP_GET_OBJECT_PROPS_SUPPORTED    0x9801
#define MTP_GET_OBJECT_PROP_DESC          0x9802
#define MTP_GET_OBJECT_PROP_VALUE         0x9803
#define MTP_SET_OBJECT_PROP_VALUE         0x9804
#define MTP_GET_OBJECT_PROP_LIST          0x9805
#define MTP_SET_OBJECT_PROP_LIST          0x9806
#define MTP_GET_INTERDEPENDENT_PROP_DESC  0x9807
#define MTP_SEND_OBJECT_PROP_LIST         0x9808
#define MTP_GET_OBJECT_REFERENCES         0x9810
#define MTP_SET_OBJECT_REFERENCES         0x9811
#define MTP_SKIP                          0x9820

#define MTP_UNDEF                     0x0000
#define MTP_INT8                        0x0001
#define MTP_UINT8                      0x0002
#define MTP_INT16                       0x0003
#define MTP_UINT16                     0x0004
#define MTP_INT32                       0x0005
#define MTP_UINT32                     0x0006
#define MTP_INT64                       0x0007
#define MTP_UINT64                     0x0008
#define MTP_INT128                      0x0009
#define MTP_UINT128                    0x000A
#define MTP_AINT8                      0x4001
#define MTP_AUINT8                    0x4002
#define MTP_AINT16                     0x4003
#define MTP_AUINT16                   0x4004
#define MTP_AINT32                     0x4005
#define MTP_AUINT32                   0x4006
#define MTP_AINT64                     0x4007
#define MTP_AUINT64                   0x4008
#define MTP_AINT128                    0x4009
#define MTP_AUINT128                  0x400A
#define MTP_STR                         0xFFFF

#define MTP_EVENT_UNDEFINED            0x4000
#define MTP_EVENT_CANCEL_TRANSCATION   0x4001
#define MTP_EVENT_OBJECT_ADDED         0x4002
#define MTP_EVENT_OBJECT_REMOVED       0x4003
#define MTP_EVENT_STORE_ADDED          0x4004
#define MTP_EVENT_STORE_REMOVED        0x4005
#define MTP_EVENT_DEVICE_PROP_CHANGED  0x4006
#define MTP_EVENT_OBJECT_INFO_CHANGED  0x4007
#define MTP_EVENT_DEVICE_INFO_CHANGED  0x4008
#define MTP_EVENT_REQ_OBJECT_TRANSFER  0x4009
#define MTP_EVENT_STORE_FULL           0x400A
#define MTP_EVENT_DEVICE_RESET         0x400B
#define MTP_EVENT_STORAGE_INFO_CHANGED 0x400C
#define MTP_EVENT_CAPTURE_COMPLETE     0x400D
#define MTP_EVENT_UNREPORTED_STATUS    0x400E
#define MTP_EVENT_OBJECT_PROP_CHANGED  0xC801
#define MTP_EVENT_OBJECT_PROP_DESC_CHANGED 0xC802
#define MTP_EVENT_OBJECT_REF_CHANGED   0xC803

#define MTP_FORM_NONE          0x00
#define MTP_FORM_RANGE         0x01
#define MTP_FORM_ENUMERATION   0x02
#define MTP_FORM_DATE_TIME     0x03
#define MTP_FORM_FIXED_LEN_ARR 0x04
#define MTP_FORM_REG_EXP       0x05
#define MTP_FORM_BYTE_ARR      0x06
#define MTP_FORM_LONG_STR      0x08


static const value_string form_flag_vals[] = {
    {0x00, "None"},
    {0x01, "Range form"},
    {0x02, "Enumeration form"},
    {0x03, "DateTime form"},
    {0x04, "Fixed-length Array form"},
    {0x05, "Regular Expression form"},
    {0x06, "ByteArray form"},
    {0xFF, "LongString form"}
};


static const value_string access_capability_vals [] = {
    {0x0000, "Read-write" },
    {0x0001, "Read-only without object deletion" },
    {0x0002, "Read-only with object deletion" },
    {0, NULL}
};

static const value_string get_set_vals[] = {
    {0x00, "Get"},
    {0x01, "Get/Set"},
    {0, NULL},
};


static const value_string storage_type_vals[] = {
    {0x0000,      "Undefined"},
    {0x0001,      "Fixed ROM"},
    {0x0002,      "Removable ROM"},
    {0x0003,      "Fixed RAM"},
    {0x0004,      "Removable RAM"},
    {0,      NULL},
};

static const value_string data_type_vals[] = {
    {0x0000,      "UNDEF"},
    {0x0001,      "INT8"},
    {0x0002,      "UINT8"},
    {0x0003,      "INT16"},
    {0x0004,      "UINT16"},
    {0x0005,      "INT32"},
    {0x0006,      "UINT32"},
    {0x0007,      "INT64"},
    {0x0008,      "UINT64"},
    {0x0009,      "INT128"},
    {0x000A,      "UINT128"},
    {0x4001,      "AINT8"},
    {0x4002,      "AUINT8"},
    {0x4003,      "AINT16"},
    {0x4004,      "AUINT16"},
    {0x4005,      "AINT32"},
    {0x4006,      "AUINT32"},
    {0x4007,      "AINT64"},
    {0x4008,      "AUINT64"},
    {0x4009,      "AINT128"},
    {0x400A,      "AUINT128"},
    {0xFFFF,      "STR"},
    {0,      NULL},
};

static const value_string association_type_vals[] = {
    {0x0000, "Undefined"},
    {0x0001, "Generic Folder"},
    {0x0002, "Album"},
    {0x0003, "Time Sequence"},
    {0x0004, "Horizontal Panoramic"},
    {0x0005, "Vertical Panoramic"},
    {0x0006, "2D Panoramic"},
    {0x0007, "Anillary Data"}
};

static const value_string file_system_format_vals[] = {
    {0x0000, "Undefined"},
    {0x0001, "Generic flat"},
    {0x0002, "Generic hierarchical"},
    {0x0003, "DCF"},
    {0, NULL}
};

static const value_string functional_mode_vals[] = {
    {0x0000, "Standard mode"},
    {0x0001, "Sleep rate" },
    {0xC001, "Non-responsive playback" },
    {0xC002, "Responsive playback" },
    {0, NULL}
};

static const value_string object_format_vals[] = {
    {0x3000,      "Undefined"},
    {0x3001,      "Association"},
    {0x3002,      "Script"},
    {0x3003,      "Executable"},
    {0x3004,      "Text"},
    {0x3005,      "HTML"},
    {0x3006,      "DPOF"},
    {0x3007,      "AIFF"},
    {0x3008,      "WAV"},
    {0x3009,      "MP3"},
    {0x300A,      "AVI"},
    {0x300B,      "MPEG"},
    {0x300C,      "ASF"},
    {0x3800,      "Undefined Image"},
    {0x3801,      "EXIF/JPEG"},
    {0x3802,      "TIFF/EP"},
    {0x3803,      "FlashPix"},
    {0x3804,      "BMP"},
    {0x3805,      "CIFF"},
    {0x3806,      "Undefined"},
    {0x3807,      "GIF"},
    {0x3808,      "JFIF"},
    {0x3809,      "CD"},
    {0x380A,      "PICT"},
    {0x380B,      "PNG"},
    {0x380C,      "Undefined"},
    {0x380D,      "TIFF"},
    {0x380E,      "TIFF/IT"},
    {0x380F,      "JP2"},
    {0x3810,      "JPX"},
    {0xB802,      "Undefined Firmware"},
    {0xB881,      "Windows Image Format"},
    {0xB803,      "WBMP"},
    {0xB804,      "JPEG XR "},
    {0xB900,      "Undefined Audio"},
    {0xB901,      "WMA"},
    {0xB902,      "OGG"},
    {0xB903,      "AAC"},
    {0xB904,      "Audible"},
    {0xB906,      "FLAC"},
    {0xB907,      "QCELP"},
    {0xB908,      "AMR"},
    {0xB980,      "Undefined Video"},
    {0xB981,      "WMV"},
    {0xB982,      "MP4 Container"},
    {0xB983,      "MP2"},
    {0xB984,      "3GP Container"},
    {0xB985,      "3G2"},
    {0xB986,      "AVCHD"},
    {0xB987,      "ATSC-TS"},
    {0xB988,      "DVB-TS"},
    {0xBA00,      "Undefined Collection"},
    {0xBA01,      "Abstract Multimedia Album"},
    {0xBA02,      "Abstract Image Album"},
    {0xBA03,      "Abstract Audio Album"},
    {0xBA04,      "Abstract Video Album"},
    {0xBA05,      "Abstract Audio & Video Playlist"},
    {0xBA06,      "Abstract Contact Group"},
    {0xBA07,      "Abstract Message Folder"},
    {0xBA08,      "Abstract Chaptered Production"},
    {0xBA09,      "Abstract Audio Playlist"},
    {0xBA0A,      "Abstract Video Playlist"},
    {0xBA0B,      "Abstract Mediacast"},
    {0xBA10,      "WPL Playlist"},
    {0xBA11,      "M3U Playlist"},
    {0xBA12,      "MPL Playlist"},
    {0xBA13,      "ASX Playlist"},
    {0xBA14,      "PLS Playlist"},
    {0xBA80,      "Undefined Document"},
    {0xBA81,      "Abstract Document"},
    {0xBA82,      "XML Document"},
    {0xBA83,      "Microsoft Word Document"},
    {0xBA84,      "MHT Compiled HTML Document"},
    {0xBA85,      "Microsoft Excel spreadsheet (.xls)"},
    {0xBA86,      "Microsoft Powerpoint presentation (.ppt)"},
    {0xBB00,      "Undefined Message"},
    {0xBB01,      "Abstract Message"},
    {0xBB10,      "Undefined Bookmark"},
    {0xBB11,      "Abstract Bookmark"},
    {0xBB20,      "Undefined Appointment"},
    {0xBB21,      "Abstract Appointment"},
    {0xBB22,      "vCalendar 1.0"},
    {0xBB40,      "Undefined Task"},
    {0xBB41,      "Abstract Task"},
    {0xBB42,      "iCalendar"},
    {0xBB60,      "Undefined Note"},
    {0xBB61,      "Abstract Note"},
    {0xBB80,      "Undefined Contact"},
    {0xBB81,      "Abstract Contact"},
    {0xBB82,      "vCard 2"},
    {0xBB83,      "vCard 3"},
    {0,      NULL},
};

static const value_string object_property_vals[] = {
    {0xDC01,      "StorageID"},
    {0xDC02,      "Object Format"},
    {0xDC03,      "Protection Status"},
    {0xDC04,      "Object Size"},
    {0xDC05,      "Association Type"},
    {0xDC06,      "Association Desc"},
    {0xDC07,      "Object File Name"},
    {0xDC08,      "Date Created"},
    {0xDC09,      "Date Modified"},
    {0xDC0A,      "Keywords"},
    {0xDC0B,      "Parent Object"},
    {0xDC0C,      "Allowed Folder Contents"},
    {0xDC0D,      "Hidden"},
    {0xDC0E,      "System Object"},
    {0xDC41,      "Persistent Unique Object Identifier"},
    {0xDC42,      "SyncID"},
    {0xDC43,      "Property Bag"},
    {0xDC44,      "Name"},
    {0xDC45,      "Created By"},
    {0xDC46,      "Artist"},
    {0xDC47,      "Date Authored"},
    {0xDC48,      "Description"},
    {0xDC49,      "URL Reference"},
    {0xDC4A,      "Language-Locale"},
    {0xDC4B,      "Copyright Information"},
    {0xDC4C,      "Source"},
    {0xDC4D,      "Origin Location"},
    {0xDC4E,      "Date Added"},
    {0xDC4F,      "Non-Consumable"},
    {0xDC50,      "Corrupt/Unplayable"},
    {0xDC51,      "ProducerSerialNumber"},
    {0xDC81,      "Representative Sample Format"},
    {0xDC82,      "Representative Sample Size"},
    {0xDC83,      "Representative Sample Height"},
    {0xDC84,      "Representative Sample Width"},
    {0xDC85,      "Representative Sample Duration"},
    {0xDC86,      "Representative Sample Data"},
    {0xDC87,      "Width"},
    {0xDC88,      "Height"},
    {0xDC89,      "Duration"},
    {0xDC8A,      "Rating"},
    {0xDC8B,      "Track"},
    {0xDC8C,      "Genre"},
    {0xDC8D,      "Credits"},
    {0xDC8E,      "Lyrics"},
    {0xDC8F,      "Subscription Content ID"},
    {0xDC90,      "Produced By"},
    {0xDC91,      "Use Count"},
    {0xDC92,      "Skip Count"},
    {0xDC93,      "Last Accessed"},
    {0xDC94,      "Parental Rating"},
    {0xDC95,      "Meta Genre"},
    {0xDC96,      "Composer"},
    {0xDC97,      "Effective Rating"},
    {0xDC98,      "Subtitle"},
    {0xDC99,      "Original Release Date"},
    {0xDC9A,      "Album Name"},
    {0xDC9B,      "Album Artist"},
    {0xDC9C,      "Mood"},
    {0xDC9D,      "DRM Status"},
    {0xDC9E,      "Sub Description"},
    {0xDCD1,      "Is Cropped"},
    {0xDCD2,      "Is Colour Corrected"},
    {0xDCD3,      "Image Bit Depth"},
    {0xDCD4,      "Fnumber"},
    {0xDCD5,      "Exposure Time"},
    {0xDCD6,      "Exposure Index"},
    {0xDE91,      "Total BitRate"},
    {0xDE92,      "Bitrate Type"},
    {0xDE93,      "Sample Rate"},
    {0xDE94,      "Number Of Channels"},
    {0xDE95,      "Audio BitDepth"},
    {0xDE97,      "Scan Type"},
    {0xDE99,      "Audio WAVE Codec"},
    {0xDE9A,      "Audio BitRate"},
    {0xDE9B,      "Video FourCC Codec"},
    {0xDE9C,      "Video BitRate"},
    {0xDE9D,      "Frames Per Thousand Seconds"},
    {0xDE9E,      "KeyFrame Distance"},
    {0xDE9F,      "Buffer Size"},
    {0xDEA0,      "Encoding Quality"},
    {0xDEA1,      "Encoding Profile"},
    {0xDCE0,      "Display Name"},
    {0xDCE1,      "Body Text"},
    {0xDCE2,      "Subject"},
    {0xDCE3,      "Priority"},
    {0xDD00,      "Given Name"},
    {0xDD01,      "Middle Names"},
    {0xDD02,      "Family Name"},
    {0xDD03,      "Prefix"},
    {0xDD04,      "Suffix"},
    {0xDD05,      "Phonetic Given Name"},
    {0xDD06,      "Phonetic Family Name"},
    {0xDD07,      "Email Primary"},
    {0xDD08,      "Email Personal 1"},
    {0xDD09,      "Email Personal 2"},
    {0xDD0A,      "Email Business 1"},
    {0xDD0B,      "Email Business 2"},
    {0xDD0C,      "Email Others"},
    {0xDD0D,      "Phone Number Primary"},
    {0xDD0E,      "Phone Number Personal"},
    {0xDD0F,      "Phone Number Personal 2"},
    {0xDD10,      "Phone Number Business"},
    {0xDD11,      "Phone Number Business 2"},
    {0xDD12,      "Phone Number Mobile"},
    {0xDD13,      "Phone Number Mobile 2"},
    {0xDD14,      "Fax Number Primary"},
    {0xDD15,      "Fax Number Personal"},
    {0xDD16,      "Fax Number Business"},
    {0xDD17,      "Pager Number"},
    {0xDD18,      "Phone Number Others"},
    {0xDD19,      "Primary Web Address"},
    {0xDD1A,      "Personal Web Address"},
    {0xDD1B,      "Business Web Address"},
    {0xDD1C,      "Instant Messenger Address"},
    {0xDD1D,      "Instant Messenger Address 2"},
    {0xDD1E,      "Instant Messenger Address 3"},
    {0xDD1F,      "Postal Address Personal Full"},
    {0xDD20,      "Postal Address Personal Line 1"},
    {0xDD21,      "Postal Address Personal Line 2"},
    {0xDD22,      "Postal Address Personal City"},
    {0xDD23,      "Postal Address Personal Region"},
    {0xDD24,      "Postal Address Personal Postal Code"},
    {0xDD25,      "Postal Address Personal Country"},
    {0xDD26,      "Postal Address Business Full"},
    {0xDD27,      "Postal Address Business Line 1"},
    {0xDD28,      "Postal Address Business Line 2"},
    {0xDD29,      "Postal Address Business City"},
    {0xDD2A,      "Postal Address Business Region"},
    {0xDD2B,      "Postal Address Business Postal Code"},
    {0xDD2C,      "Postal Address Business Country"},
    {0xDD2D,      "Postal Address Other Full"},
    {0xDD2E,      "Postal Address Other Line 1"},
    {0xDD2F,      "Postal Address Other Line 2"},
    {0xDD30,      "Postal Address Other City"},
    {0xDD31,      "Postal Address Other Region"},
    {0xDD32,      "Postal Address Other Postal Code"},
    {0xDD33,      "Postal Address Other Country"},
    {0xDD34,      "Organization Name"},
    {0xDD35,      "Phonetic Organization Name"},
    {0xDD36,      "Role"},
    {0xDD37,      "Birthdate"},
    {0xDD40,      "Message To"},
    {0xDD41,      "Message CC"},
    {0xDD42,      "Message BCC"},
    {0xDD43,      "Message Read"},
    {0xDD44,      "Message Received Time"},
    {0xDD45,      "Message Sender"},
    {0xDD50,      "Activity Begin Time"},
    {0xDD51,      "Activity End Time"},
    {0xDD52,      "Activity Location"},
    {0xDD54,      "Activity Required Attendees"},
    {0xDD55,      "Activity Optional Attendees"},
    {0xDD56,      "Activity Resources"},
    {0xDD57,      "Activity Accepted"},
    {0xDD58,      "Activity Tentative"},
    {0xDD59,      "Activity Declined"},
    {0xDD5A,      "Activity Reminder Time"},
    {0xDD5B,      "Activity Owner"},
    {0xDD5C,      "Activity Status"},
    {0xDD5D,      "Owner"},
    {0xDD5E,      "Editor"},
    {0xDD5F,      "Webmaster"},
    {0xDD60,      "URL Source"},
    {0xDD61,      "URL Destination"},
    {0xDD62,      "Time Bookmark"},
    {0xDD63,      "Object Bookmark"},
    {0xDD64,      "Byte Bookmark"},
    {0xDD70,      "Last Build Date"},
    {0xDD71,      "Time to Live"},
    {0xDD72,      "Media GUID"},
    {0,      NULL},
};

/* TODO: handle RESERVED value */
static const value_string protection_status_vals[] = {
    {0x0000,      "No protection"},
    {0x0001,      "Read-only"},
    {0x8002,      "Read-only data"},
    {0x8003,      "Non-transferable data"},
    {0,      NULL},
};


static const value_string device_property_vals[] = {
    {0x5000,      "Undefined"},
    {0x5001,      "Battery Level"},
    {0x5002,      "Functional Mode"},
    {0x5003,      "Image Size"},
    {0x5004,      "Compression Setting"},
    {0x5005,      "White Balance"},
    {0x5006,      "RGB Gain"},
    {0x5007,      "F-Number"},
    {0x5008,      "Focal Length"},
    {0x5009,      "Focus Distance"},
    {0x500A,      "Focus Mode"},
    {0x500B,      "Exposure Metering Mode"},
    {0x500C,      "Flash Mode"},
    {0x500D,      "Exposure Time"},
    {0x500E,      "Exposure Program Mode"},
    {0x500F,      "Exposure Index"},
    {0x5010,      "Exposure Bias Compensation"},
    {0x5011,      "DateTime"},
    {0x5012,      "Capture Delay"},
    {0x5013,      "Still Capture Mode"},
    {0x5014,      "Contrast"},
    {0x5015,      "Sharpness"},
    {0x5016,      "Digital Zoom"},
    {0x5017,      "Effect Mode"},
    {0x5018,      "Burst Number"},
    {0x5019,      "Burst Interval"},
    {0x501A,      "Timelapse Number"},
    {0x501B,      "Timelapse Interval"},
    {0x501C,      "Focus Metering Mode"},
    {0x501D,      "Upload URL"},
    {0x501E,      "Artist"},
    {0x501F,      "Copyright Info"},
    {0xD401,      "Synchronization Partner"},
    {0xD402,      "Device Friendly Name"},
    {0xD403,      "Volume"},
    {0xD404,      "SupportedFormatsOrdered"},
    {0xD405,      "DeviceIcon"},
    {0xD410,      "Playback Rate"},
    {0xD411,      "Playback Object"},
    {0xD412,      "Playback Container Index"},
    {0xD406,      "Session Initiator Version Info"},
    {0xD407,      "Perceived Device Type"},
    {0,      NULL},
};


static const value_string mtp_op_name_vals[] = {
    {0x1001,      "GetDeviceInfo"},
    {0x1002,      "OpenSession"},
    {0x1003,      "CloseSession"},
    {0x1004,      "GetStorageIDs"},
    {0x1005,      "GetStorageInfo"},
    {0x1006,      "GetNumObjects"},
    {0x1007,      "GetObjectHandles"},
    {0x1008,      "GetObjectInfo"},
    {0x1009,      "GetObject"},
    {0x100A,      "GetThumb"},
    {0x100B,      "DeleteObject"},
    {0x100C,      "SendObjectInfo"},
    {0x100D,      "SendObject"},
    {0x100E,      "InitiateCapture"},
    {0x100F,      "FormatStore"},
    {0x1010,      "ResetDevice"},
    {0x1011,      "SelfTest"},
    {0x1012,      "SetObjectProtection"},
    {0x1013,      "PowerDown"},
    {0x1014,      "GetDevicePropDesc"},
    {0x1015,      "GetDevicePropValue"},
    {0x1016,      "SetDevicePropValue"},
    {0x1017,      "ResetDevicePropValue"},
    {0x1018,      "TerminateOpenCapture"},
    {0x1019,      "MoveObject"},
    {0x101A,      "CopyObject"},
    {0x101B,      "GetPartialObject"},
    {0x101C,      "InitiateOpenCapture"},
    {0x9801,      "GetObjectPropsSupported"},
    {0x9802,      "GetObjectPropDesc"},
    {0x9803,      "GetObjectPropValue"},
    {0x9804,      "SetObjectPropValue"},
    {0x9805,      "GetObjectPropList"},
    {0x9806,      "SetObjectPropList"},
    {0x9807,      "GetInterdependentPropDesc"},
    {0x9808,      "SendObjectPropList"},
    {0x9810,      "GetObjectReferences"},
    {0x9811,      "SetObjectReferences"},
    {0x9820,      "Skip"},
    {0,      NULL},
};

static const value_string mtp_response_vals[] = {
    {0x2000,      "Undefined"},
    {0x2001,      "OK"},
    {0x2002,      "General_Error"},
    {0x2003,      "Session_Not_Open"},
    {0x2004,      "Invalid_TransactionID"},
    {0x2005,      "Operation_Not_Supported"},
    {0x2006,      "Parameter_Not_Supported"},
    {0x2007,      "Incomplete_Transfer"},
    {0x2008,      "Invalid_StorageID"},
    {0x2009,      "Invalid_ObjectHandle"},
    {0x200A,      "DeviceProp_Not_Supported"},
    {0x200B,      "Invalid_ObjectFormatCode"},
    {0x200C,      "Store_Full"},
    {0x200D,      "Object_WriteProtected"},
    {0x200E,      "Store_Read-Only"},
    {0x200F,      "Access_Denied"},
    {0x2010,      "No_Thumbnail_Present"},
    {0x2011,      "SelfTest_Failed"},
    {0x2012,      "Partial_Deletion"},
    {0x2013,      "Store_Not_Available"},
    {0x2014,      "Specification_By_Format_Unsupported"},
    {0x2015,      "No_Valid_ObjectInfo"},
    {0x2016,      "Invalid_Code_Format"},
    {0x2017,      "Unknown_Vendor_Code"},
    {0x2018,      "Capture_Already_Terminated"},
    {0x2019,      "Device_Busy"},
    {0x201A,      "Invalid_ParentObject"},
    {0x201B,      "Invalid_DeviceProp_Format"},
    {0x201C,      "Invalid_DeviceProp_Value"},
    {0x201D,      "Invalid_Parameter"},
    {0x201E,      "Session_Already_Open"},
    {0x201F,      "Transaction_Cancelled"},
    {0x2020,      "Specification_of_Destination_Unsupported"},
    {0xA801,      "Invalid_ObjectPropCode"},
    {0xA802,      "Invalid_ObjectProp_Format"},
    {0xA803,      "Invalid_ObjectProp_Value"},
    {0xA804,      "Invalid_ObjectReference"},
    {0xA805,      "Group_Not_Supported"},
    {0xA806,      "Invalid_Dataset"},
    {0xA807,      "Specification_By_Group_Unsupported"},
    {0xA808,      "Specification_By_Depth_Unsupported"},
    {0xA809,      "Object_Too_Large"},
    {0xA80A,      "ObjectProp_Not_Supported"},
    {0,      NULL},
};

static const value_string mtp_event_vals[] = {
    {0x4000,      "Undefined"},
    {0x4001,      "CancelTransaction"},
    {0x4002,      "ObjectAdded"},
    {0x4003,      "ObjectRemoved"},
    {0x4004,      "StoreAdded"},
    {0x4005,      "StoreRemoved"},
    {0x4006,      "DevicePropChanged"},
    {0x4007,      "ObjectInfoChanged"},
    {0x4008,      "DeviceInfoChanged"},
    {0x4009,      "RequestObjectTransfer"},
    {0x400A,      "StoreFull"},
    {0x400B,      "DeviceReset"},
    {0x400C,      "StorageInfoChanged"},
    {0x400D,      "CaptureComplete"},
    {0x400E,      "UnreportedStatus"},
    {0xC801,      "ObjectPropChanged"},
    {0xC802,      "ObjectPropDescChanged"},
    {0xC803,      "ObjectReferencesChanged"},
    {0,      NULL},
};


static const value_string mtp_container_type_vals[] = {
    { MTP_TYPE_CMD,      "Command Block"},
    { MTP_TYPE_DATA,     "Data Block"},
    { MTP_TYPE_RESPONSE, "Response Block"},
    { MTP_TYPE_EVENT,    "Event Block"},
    {0, NULL}
};

static const value_string mtp_packet_type_vals[] = {
    { MTP_TYPE_CMD,      "CMD"},
    { MTP_TYPE_DATA,     "DATA"},
    { MTP_TYPE_RESPONSE, "RESPONSE"},
    { MTP_TYPE_EVENT,    "EVENT"},
    {0, NULL}
};


static gint16 op_code;

static gint
mtp_dissect_array(tvbuff_t *tvb, proto_tree *tree, gint offset,
                  const char *array_name, int hf_index, guint elem_size)
{
    proto_tree *array_tree;
    guint32 i;
    guint32 n_elems = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);

    offset += 4;

    array_tree = proto_tree_add_subtree_format(tree, tvb, offset, n_elems * elem_size,
                                               ett_mtp_array, NULL, "%s [%d]",
                                               array_name, n_elems);


    for (i = 0; i < n_elems; i++) {
        proto_tree_add_item(array_tree, hf_index, tvb, offset,
                            elem_size, ENC_LITTLE_ENDIAN);

        offset += elem_size;
    }

    return offset;
}

static gint
mtp_dissect_string(tvbuff_t *tvb, proto_tree *tree, gint offset,
                   int hf_index)
{
    guint8 len = tvb_get_guint8(tvb, offset);

    offset += 1;

    proto_tree_add_item(tree, hf_index, tvb, offset,
                        len * 2, ENC_UTF_16 | ENC_LITTLE_ENDIAN);

    /* Strings are UTF16 */
    return offset + 2 * len;
}


static gint
mtp_dissect_dynamic_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset,
                         guint16 datatype, int hfindex)
{
    gboolean is_array = datatype & 0x4000;

    if (datatype == MTP_STR)
        return mtp_dissect_string(tvb, tree, offset, hfindex);

    datatype &= ~(0x4000);
    guint length = 1 << ((datatype - 1) / 2);

    if (is_array) {
        return mtp_dissect_array(tvb, tree, offset, "Data Array", hfindex, length);
    } else {
        proto_tree_add_item(tree, hfindex, tvb, offset, length, ENC_LITTLE_ENDIAN);
        return offset + length;
    }

}

static gint
mtp_dissect_device_info_dataset(tvbuff_t *tvb, proto_tree *tree,
                                gint offset)
{
    proto_tree *dev_info_tree;

    dev_info_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_dev_info, NULL,
                                           "Device Info Dataset");

    proto_tree_add_item(dev_info_tree, hf_standard_version, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(dev_info_tree, hf_vendor_extension_id, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(dev_info_tree, hf_mtp_version, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    offset = mtp_dissect_string(tvb, dev_info_tree, offset, hf_mtp_extensions);

    proto_tree_add_item(dev_info_tree, hf_functional_mode, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    offset = mtp_dissect_array(tvb, dev_info_tree, offset,
                               "Operations Supported", hf_operation_code, 2);

    offset = mtp_dissect_array(tvb, dev_info_tree, offset, "Events supported",
                               hf_event_code, 2);

    offset = mtp_dissect_array(tvb, dev_info_tree,
                               offset, "Device Properties Supported",
                               hf_device_prop_code, 2);

    offset = mtp_dissect_array(tvb, dev_info_tree, offset,
                               "Capture Formats", hf_object_format_code, 2);

    offset = mtp_dissect_array(tvb, dev_info_tree, offset,
                               "Playback Formats", hf_object_format_code, 2);

    offset = mtp_dissect_string(tvb, dev_info_tree, offset, hf_manufacturer);

    offset = mtp_dissect_string(tvb, dev_info_tree, offset, hf_model);

    offset = mtp_dissect_string(tvb, dev_info_tree, offset, hf_device_version);

    offset = mtp_dissect_string(tvb, dev_info_tree, offset, hf_serial_number);

    return offset;
}

static gint
mtp_dissect_object_prop_desc_dataset(tvbuff_t *tvb,
                                     proto_tree *tree, gint offset)
{
    proto_tree *prop_desc_tree;
    guint16 datatype;
    guint16 n_values, i;

    prop_desc_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_prop_desc, NULL,
                                           "ObjectPropDesc dataset");

    proto_tree_add_item(prop_desc_tree, hf_object_prop_code, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    datatype = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(prop_desc_tree, hf_datatype, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(prop_desc_tree, hf_get_set, tvb,
                        offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    offset = mtp_dissect_dynamic_type(tvb, prop_desc_tree, offset, datatype, hf_default_value);

    proto_tree_add_item(prop_desc_tree, hf_group_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    guint8 form_flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(prop_desc_tree, hf_form_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    switch (form_flag) {
    case MTP_FORM_NONE:
        break;
    case MTP_FORM_RANGE:
        offset = mtp_dissect_dynamic_type(tvb, prop_desc_tree,
                                          offset, datatype, hf_minimum_value);
        offset = mtp_dissect_dynamic_type(tvb, prop_desc_tree,
                                          offset, datatype, hf_maximum_value);
        offset = mtp_dissect_dynamic_type(tvb, prop_desc_tree,
                                          offset, datatype, hf_step_size);
        break;
    case MTP_FORM_ENUMERATION:
        n_values = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        for (i = 0; i < n_values; i++) {
            offset = mtp_dissect_dynamic_type(tvb, prop_desc_tree,
                                          offset, datatype, hf_supported_value);
        }
        break;
    case MTP_FORM_DATE_TIME:
        offset = mtp_dissect_string(tvb, prop_desc_tree, offset, hf_date_time);
        break;
    case MTP_FORM_FIXED_LEN_ARR:
        proto_tree_add_item(prop_desc_tree, hf_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;
    case MTP_FORM_REG_EXP:
        offset = mtp_dissect_string(tvb, prop_desc_tree, offset, hf_regexp);
        break;
    case MTP_FORM_LONG_STR:
    case MTP_FORM_BYTE_ARR:
        proto_tree_add_item(prop_desc_tree, hf_max_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
    }

    return offset;
}

static gint
mtp_dissect_storage_info_dataest(tvbuff_t *tvb,
                                     proto_tree *tree, gint offset)
{
    proto_tree *storage_info_tree;

    storage_info_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_storage_info, NULL,
                                               "StorageInfo dataset");

    proto_tree_add_item(storage_info_tree, hf_storage_type, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(storage_info_tree, hf_file_system_format, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(storage_info_tree, hf_access_capability, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(storage_info_tree, hf_max_capacity, tvb,
                        offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(storage_info_tree, hf_free_space, tvb,
                        offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    proto_tree_add_item(storage_info_tree, hf_free_space_objects, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset = mtp_dissect_string(tvb, storage_info_tree, offset, hf_storage_description);

    offset = mtp_dissect_string(tvb, storage_info_tree, offset, hf_volume_identifier);

    return offset;
}

static void
mtp_dissect_object_info_dataset(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *object_info_tree;

    object_info_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_object_info, NULL,
                                               "ObjectInfo dataset");

    proto_tree_add_item(object_info_tree, hf_storage_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_object_format_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(object_info_tree, hf_protection_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(object_info_tree, hf_object_compressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_thumb_format, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(object_info_tree, hf_thumb_compressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_thumb_pix_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_thumb_pix_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_image_pix_width, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_image_pix_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_image_bit_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_parent_object, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_association_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(object_info_tree, hf_association_desc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(object_info_tree, hf_sequence_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    offset = mtp_dissect_string(tvb, object_info_tree, offset, hf_filename);

    offset = mtp_dissect_string(tvb, object_info_tree, offset, hf_date_created);

    offset = mtp_dissect_string(tvb, object_info_tree, offset, hf_date_modified);

    offset = mtp_dissect_string(tvb, object_info_tree, offset, hf_keywords);
}

static void
mtp_dissect_device_prop_desc(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *dev_prop_tree;
    guint16 datatype;
    guint16 n_values, i;

    dev_prop_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_dev_prop_desc, NULL,
                                           "DevicePropertyDesc dataset");

    proto_tree_add_item(dev_prop_tree, hf_device_prop_code, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    datatype = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(dev_prop_tree, hf_datatype, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(dev_prop_tree, hf_get_set, tvb,
                        offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree, offset, datatype, hf_factory_default_value);
    offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree, offset, datatype, hf_current_value);

    guint8 form_flag = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(dev_prop_tree, hf_form_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    switch (form_flag) {
    case MTP_FORM_NONE:
        break;
    case MTP_FORM_RANGE:
        offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree,
                                          offset, datatype, hf_minimum_value);
        offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree,
                                          offset, datatype, hf_maximum_value);

        offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree,
                                          offset, datatype, hf_step_size);
        break;
    case MTP_FORM_ENUMERATION:
        n_values = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        for (i = 0; i < n_values; i++) {
            offset = mtp_dissect_dynamic_type(tvb, dev_prop_tree,
                                          offset, datatype, hf_supported_value);
        }
        break;
    }
}

static void
mtp_dissect_object_prop_list(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    proto_tree *object_prop_list_tree;
    guint16 datatype;
    guint32 n_elements, i;

    object_prop_list_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mtp_object_prop_list, NULL,
                                                  "ObjectPropList dataset");

    n_elements = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(object_prop_list_tree, hf_number_of_elements,
                        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    for (i = 0; i < n_elements; i++) {
        proto_tree *element_tree = proto_tree_add_subtree_format(object_prop_list_tree, tvb, offset, -1, ett_mtp_object_prop_list, NULL,
                                                                "Element[%d]", i);
        proto_tree_add_item(element_tree, hf_object_handle,
                            tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(element_tree, hf_object_prop_code,
                            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        datatype = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(element_tree, hf_datatype,
                            tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (datatype == MTP_STR)
            offset = mtp_dissect_string(tvb, element_tree, offset, hf_value_str);
        else
            offset = mtp_dissect_dynamic_type(tvb, element_tree, offset, datatype, hf_value);
    }

}

static gint
mtp_dissect_interdependent_prop_desc(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    guint16 n_interdependencies = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    guint16 i;

    proto_tree_add_item(tree, hf_n_interdependencies, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    for (i = 0; i < n_interdependencies; i++) {
        guint16 n_prop_descs = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        guint16 j;

        proto_tree *inter_arr_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mtp_object_prop_list, NULL,
                                                                   "Interdepencies array[%d]", i);

        proto_tree_add_item(inter_arr_tree, hf_n_interdependencies, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        for (j = 0; j < n_prop_descs; j++) {
            proto_tree *inter_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mtp_object_prop_list, NULL,
                                                                   "Interdepency [%d][%d]", i, j);

            offset = mtp_dissect_object_prop_desc_dataset(tvb, inter_tree, offset);
        }

    }

    return offset;
}

static void
mtp_dissect_command_parameters(tvbuff_t *tvb, proto_tree *tree, gint offset,
                           int params[], guint n_params)
{
    proto_tree *params_tree;

     /* there is a session ID */
    if (tvb_reported_length_remaining(tvb, offset) == 8 + (gint) n_params * 4 ) {
        proto_tree_add_item(tree, hf_session_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);

        offset += 4;
    }

    proto_tree_add_item(tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    params_tree = proto_tree_add_subtree(tree, tvb, offset,
                                         tvb_reported_length_remaining(tvb, offset),
                                         ett_mtp_parameters, NULL, "Parameters");
    guint i;
    for (i = 0; i < n_params; i++) {
        proto_tree_add_item(params_tree, params[i], tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }
}

static void
mtp_dissect_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    int params[5] = {};
    int n_params = 0;
    guint16 cmd_op;

    cmd_op = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_operation_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(cmd_op, mtp_op_name_vals, "Unknown (0x%02x)"));

    op_code = cmd_op;

    offset += 2;

    switch (cmd_op) {
        case MTP_GET_DEVICE_INFO: case MTP_CLOSE_SESSION: case MTP_GET_STORAGE_IDS:
        case MTP_SEND_OBJECT:     case MTP_RESET_DEVICE:  case MTP_POWER_DOWN:
        case MTP_SET_OBJECT_PROP_LIST:
            n_params = 0;
            break;
        case MTP_OPEN_SESSION:
            params[0] = hf_session_id;
            n_params = 1;
            break;
        case MTP_GET_STORAGE_INFO:
            params[0] = hf_storage_id;
            n_params = 1;
            break;
        case MTP_GET_NUM_OBJECTS: case MTP_GET_OBJECT_HANDLES:
            params[0] = hf_storage_id;
            params[1] = hf_object_format_code;
            params[2] = hf_object_handle;
            n_params = 3;
            break;
        case MTP_GET_OBJECT_INFO: case MTP_GET_OBJECT: case MTP_GET_THUMB:
            params[0] = hf_object_handle;
            n_params = 1;
            break;
        case MTP_DELETE_OBJECT:
            params[0] = hf_object_handle;
            params[1] = hf_object_format_code;
            n_params = 2;
            break;
        case MTP_SEND_OBJECT_INFO:
            params[0] = hf_storage_id;
            params[1] = hf_object_handle;
            n_params = 2;
            break;
        case MTP_GET_OBJECT_PROP_DESC:
            params[0] = hf_object_prop_code;
            params[1] = hf_object_format_code;
            n_params = 2;
            break;
        case MTP_INITIATE_CAPTURE: case MTP_INITIATE_OPEN_CAPTURE:
            params[0] = hf_storage_id;
            params[1] = hf_object_format_code;
            n_params = 2;
            break;
        case MTP_FORMAT_STORE:
            params[0] = hf_storage_id;
            params[1] = hf_file_system_format;
            n_params = 2;
            break;
        case MTP_SELF_TEST:
            params[0] = hf_self_test_type;
            n_params = 1;
            break;
        case MTP_SET_OBJECT_PROTECTION:
            params[0] = hf_object_handle;
            params[1] = hf_protection_status;
            n_params = 2;
            break;
        case MTP_GET_DEVICE_PROP_DESC: case MTP_GET_DEVICE_PROP_VALUE:
        case MTP_SET_DEVICE_PROP_VALUE: case MTP_RESET_DEVICE_PROP_VALUE:
            params[0] = hf_device_prop_code;
            n_params = 1;
            break;
        case MTP_TERMINATE_OPEN_CAPTURE:
            params[0] = hf_transaction_id;
            n_params = 1;
            break;
        case MTP_MOVE_OBJECT: case MTP_COPY_OBJECT:
            params[0] = hf_object_handle;
            params[1] = hf_storage_id;
            params[2] = hf_object_handle;
            n_params = 3;
            break;
        case MTP_GET_PARTIAL_OBJECT:
            params[0] = hf_object_handle;
            params[1] = hf_offset;
            params[2] = hf_max_n_bytes;
            n_params = 3;
            break;
        case MTP_GET_OBJECT_PROPS_SUPPORTED: case MTP_GET_INTERDEPENDENT_PROP_DESC:
            params[0] = hf_object_format_code;
            n_params = 1;
            break;
        case MTP_GET_OBJECT_PROP_VALUE: case MTP_SET_OBJECT_PROP_VALUE:
            params[0] = hf_object_handle;
            params[1] = hf_object_prop_code;
            n_params = 2;
            break;
        case MTP_GET_OBJECT_REFERENCES: case MTP_SET_OBJECT_REFERENCES:
            params[0] = hf_object_handle;
            n_params = 1;
            break;
        case MTP_SKIP:
            params[0] = hf_skip_index;
            n_params = 1;
            break;
        case MTP_GET_OBJECT_PROP_LIST:
            params[0] = hf_object_handle;
            params[1] = hf_object_format_code;
            params[2] = hf_object_prop_code;
            params[3] = hf_object_prop_group_code;
            params[4] = hf_depth;
            n_params = 5;
            break;
        case MTP_SEND_OBJECT_PROP_LIST:
            params[0] = hf_storage_id;
            params[1] = hf_object_handle;
            params[2] = hf_object_format_code;
            break;
            // TODO: INT64 read
        default:
            return;
    }

    mtp_dissect_command_parameters(tvb, tree, offset, params, n_params);
}

static void
mtp_dissect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint16 response_code = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_response_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(response_code, mtp_response_vals, "Unknown (0x%02x)"));

    proto_tree_add_item(tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree *params_tree = proto_tree_add_subtree(tree, tvb, offset,
                                                     tvb_reported_length_remaining(tvb, offset),
                                                     ett_mtp_parameters, NULL, "Response Parameters");

    if (!PINFO_FD_VISITED(pinfo)) {
        guint16 *cmd_op = wmem_new0(wmem_file_scope(), guint16);

        *cmd_op = op_code;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_mtp, pinfo->num, cmd_op);
    } else {
        guint16 *cmd_op = (guint16 *) p_get_proto_data(wmem_file_scope(), pinfo,
                                                   proto_mtp, pinfo->num);

        op_code = *cmd_op;
    }

    switch (op_code) {
        case MTP_GET_NUM_OBJECTS:
            proto_tree_add_item(params_tree, hf_num_objects, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
        case MTP_SEND_OBJECT_INFO:
            proto_tree_add_item(params_tree, hf_storage_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(params_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(params_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;
        case MTP_COPY_OBJECT:
            proto_tree_add_item(params_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;

        case MTP_GET_PARTIAL_OBJECT:
            proto_tree_add_item(params_tree, hf_bytes_sent, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;

        case MTP_SEND_OBJECT_PROP_LIST:
            proto_tree_add_item(params_tree, hf_storage_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(params_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(params_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item(params_tree, hf_failed_property, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            break;
    }
}

static void
mtp_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mtp_tree, gint offset)
{
    guint16 operation_code = tvb_get_letohs(tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(operation_code, mtp_op_name_vals, "Unknown (0x%02x)"));

    proto_tree_add_item(mtp_tree, hf_operation_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(mtp_tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch (operation_code) {
    case MTP_GET_DEVICE_INFO:
        mtp_dissect_device_info_dataset(tvb, mtp_tree, offset);
        break;
    case MTP_GET_STORAGE_IDS:
        mtp_dissect_array(tvb, mtp_tree, offset, "StorageID Array", hf_storage_id, 4);
        break;
    case MTP_GET_STORAGE_INFO:
        mtp_dissect_storage_info_dataest(tvb, mtp_tree, offset);
        break;
    case MTP_GET_OBJECT_INFO:
        mtp_dissect_object_info_dataset(tvb, mtp_tree, offset);
        break;
    case MTP_GET_OBJECT: case MTP_SEND_OBJECT:
        proto_tree_add_item(mtp_tree, hf_object_binary_data, tvb, offset, -1, ENC_LITTLE_ENDIAN);
        break;
    case MTP_GET_THUMB:
        proto_tree_add_item(mtp_tree, hf_thumbnail_data, tvb, offset, -1, ENC_LITTLE_ENDIAN);
        break;
    case MTP_SEND_OBJECT_INFO:
        mtp_dissect_object_info_dataset(tvb, mtp_tree, offset);
        break;
    case MTP_GET_DEVICE_PROP_DESC:
        mtp_dissect_device_prop_desc(tvb, mtp_tree, offset);
        break;
    case MTP_GET_DEVICE_PROP_VALUE: case MTP_SET_DEVICE_PROP_VALUE:
        proto_tree_add_item(mtp_tree, hf_device_prop_value, tvb, offset, -1, ENC_LITTLE_ENDIAN);
        break;
    case MTP_GET_OBJECT_PROPS_SUPPORTED:
        mtp_dissect_array(tvb, mtp_tree, offset, "ObjectPropCode Array", hf_object_prop_code, 2);
        break;
    case MTP_GET_OBJECT_PROP_DESC:
        mtp_dissect_object_prop_desc_dataset(tvb, mtp_tree, offset);
        break;
    case MTP_GET_OBJECT_PROP_VALUE: case MTP_SET_OBJECT_PROP_VALUE:
        proto_tree_add_item(mtp_tree, hf_object_prop_value, tvb, offset, -1, ENC_LITTLE_ENDIAN);
        break;
    case MTP_GET_OBJECT_REFERENCES: case MTP_SET_OBJECT_REFERENCES: case MTP_GET_OBJECT_HANDLES:
        mtp_dissect_array(tvb, mtp_tree, offset, "ObjectHandle Array", hf_object_handle, 4);
        break;
    case MTP_GET_OBJECT_PROP_LIST: case MTP_SET_OBJECT_PROP_LIST: case MTP_SEND_OBJECT_PROP_LIST:
        mtp_dissect_object_prop_list(tvb, mtp_tree, offset);
        break;
    case MTP_GET_INTERDEPENDENT_PROP_DESC:
        mtp_dissect_interdependent_prop_desc(tvb, mtp_tree, offset);
        break;
    }
}

static void
mtp_dissect_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mtp_tree, gint offset)
{
    guint16 event_code = tvb_get_letohs(tvb, offset);

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(event_code, mtp_event_vals, "Unknown (0x%02x)"));
    proto_tree_add_item(mtp_tree, hf_event_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(mtp_tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    switch (event_code) {
    case MTP_EVENT_OBJECT_ADDED: case MTP_EVENT_OBJECT_REMOVED: case MTP_EVENT_OBJECT_INFO_CHANGED:
    case MTP_EVENT_REQ_OBJECT_TRANSFER: case MTP_EVENT_OBJECT_REF_CHANGED:
        proto_tree_add_item(mtp_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case MTP_EVENT_STORE_ADDED: case MTP_EVENT_STORE_REMOVED: case MTP_EVENT_STORE_FULL:
    case MTP_EVENT_STORAGE_INFO_CHANGED:
        proto_tree_add_item(mtp_tree, hf_storage_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case MTP_EVENT_DEVICE_PROP_CHANGED:
        proto_tree_add_item(mtp_tree, hf_device_prop_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case MTP_EVENT_CAPTURE_COMPLETE:
        proto_tree_add_item(mtp_tree, hf_transaction_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case MTP_EVENT_OBJECT_PROP_CHANGED:
        proto_tree_add_item(mtp_tree, hf_object_handle, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(mtp_tree, hf_object_prop_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    case MTP_EVENT_OBJECT_PROP_DESC_CHANGED:
        proto_tree_add_item(mtp_tree, hf_object_prop_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(mtp_tree, hf_object_format_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        break;
    default:
        break;
    }

}

static int
dissect_mtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_tree *mtp_tree;
    proto_item *ti;
    gint offset;
    guint16 mtp_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP");

    ti = proto_tree_add_protocol_format(tree, proto_mtp, tvb, 0, -1, "MTP");
    mtp_tree = proto_item_add_subtree(ti, ett_mtp);

    offset = 0;
    proto_tree_add_item(mtp_tree, hf_container_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(mtp_tree, hf_container_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    mtp_type = tvb_get_letohs(tvb,offset);
    offset += 2;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(mtp_type, mtp_packet_type_vals, "Unknown (0x%02x)"));
    switch (mtp_type) {
        case MTP_TYPE_DATA:
            mtp_dissect_data(tvb, pinfo, mtp_tree, offset);
            break;
        case MTP_TYPE_CMD:
            mtp_dissect_command(tvb, pinfo, mtp_tree, offset);
            break;
        case MTP_TYPE_RESPONSE:
            mtp_dissect_response(tvb, pinfo, mtp_tree, offset);
            break;
        case MTP_TYPE_EVENT:
            mtp_dissect_event(tvb, pinfo, mtp_tree, offset);
            break;
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

static gboolean
heur_dissect_mtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info = (usb_conv_info_t *) data;

    if (usb_conv_info && usb_conv_info->string_desc &&
        strstr((const char *) usb_conv_info->string_desc, "MTP")) {
        dissect_mtp(tvb, pinfo, tree, data);
        return TRUE;
    }

    return FALSE;
}

void
proto_register_mtp(void)
{
    proto_mtp = proto_register_protocol (
        "Media Transfer Protocol",
        "MTP",
        "mtp"
    );

    /* register arrays */
    static hf_register_info hf[] = {
        { &hf_container_length,
          { "Container Length", "mtp.container_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_container_type,
          { "Container Type", "mtp.container_type",
             FT_UINT16 , BASE_HEX, VALS(mtp_container_type_vals),
             0x0, NULL, HFILL }},
        { &hf_operation_code,
          { "Operation Code", "mtp.operation_code",
             FT_UINT16, BASE_HEX, VALS(mtp_op_name_vals),
             0x0, NULL, HFILL }},
        { &hf_response_code,
          { "Response Code", "mtp.response_code",
             FT_UINT16 , BASE_HEX, VALS(mtp_response_vals),
             0x0, NULL, HFILL }},
        { &hf_event_code,
          { "Event Code", "mtp.event_code",
             FT_UINT16, BASE_HEX, VALS(mtp_event_vals),
             0x0, NULL, HFILL }},
        { &hf_session_id,
          { "Session ID", "mtp.session_id",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_transaction_id,
          { "Transaction ID", "mtp.transaction_id",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_object_prop_code,
          { "ObjectPropCode", "mtp.object_prop_code",
            FT_UINT32, BASE_HEX, VALS(object_property_vals),
            0x0, NULL, HFILL }},
        { &hf_object_format_code,
          { "Object Format Code", "mtp.object_format_code",
            FT_UINT16, BASE_HEX, VALS(object_format_vals),
            0x0, NULL, HFILL }},
        { &hf_storage_id,
          { "StorageID", "mtp.storage_id",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_object_handle,
          { "ObjectHandle", "mtp.object_handle",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_device_prop_code,
          { "Device Property Code", "mtp.device_property_code",
            FT_UINT16, BASE_HEX, VALS(device_property_vals),
            0x0, NULL, HFILL }},
        { &hf_offset,
          { "Offset in bytes", "mtp.offset",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_max_n_bytes,
          { "Maximum number of bytes to obtain", "mtp.max_n_bytes",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_protection_status,
          { "Protection Status", "mtp.protection_status",
            FT_UINT32, BASE_HEX, VALS(protection_status_vals),
            0x0, NULL, HFILL }},
        { &hf_object_prop_group_code,
          { "Object Property Group Code", "mtp.object_prop_group_code",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_depth,
          { "Depth", "mtp.depth",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_skip_index,
          { "Skip Index", "mtp.skip_index",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_self_test_type,
          { "ObjectHandle", "mtp.object_handle",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_file_system_format,
            { "FileSystem Format", "mtp.file_system_format",
            FT_UINT16, BASE_HEX, VALS(file_system_format_vals),
            0x0, NULL, HFILL }},
        { &hf_standard_version,
            { "Standard Version", "mtp.file_system_format",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_vendor_extension_id,
            { "MTP Vendor Extension ID", "mtp.dev_info.vendor_extension_id",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_mtp_version,
            { "MTP Version", "mtp.mtp_version",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_functional_mode,
            { "Functional Mode", "mtp.functional_info",
            FT_UINT16, BASE_DEC, VALS(functional_mode_vals),
            0x0, NULL, HFILL }},
        { &hf_mtp_extensions,
            { "MTP Extensions", "mtp.mtp_extensions",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_manufacturer,
            { "Manufacturer", "mtp.manufacturer",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_model,
            { "Model", "mtp.model",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_device_version,
            { "Device Version", "mtp.dev_version",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_serial_number,
            { "Serial Number", "mtp.serial_number",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_datatype,
            { "Datatype", "mtp.datatype",
            FT_UINT16, BASE_DEC, VALS(data_type_vals),
            0x0, NULL, HFILL }},
        { &hf_storage_type,
            { "Storage Type", "mtp.storage_type",
            FT_UINT16, BASE_DEC, VALS(storage_type_vals),
            0x0, NULL, HFILL }},
        { &hf_factory_default_value,
            { "Factory Default Value", "mtp.factory_default_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_current_value,
            { "Current Value", "mtp.current_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_get_set,
            { "Get/Set", "mtp.get_set",
            FT_UINT8, BASE_HEX, VALS(get_set_vals),
            0x0, NULL, HFILL }},
        { &hf_default_value,
            { "Default Value", "mtp.default_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_access_capability,
            { "Access capability", "mtp.access_capability",
            FT_UINT16, BASE_DEC, VALS(access_capability_vals),
            0x0, NULL, HFILL }},
        { &hf_max_capacity,
            { "Max Capacity", "mtp.max_capacity",
            FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_free_space,
            { "Free Space In Bytes", "mtp.free_space",
            FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_free_space_objects,
            { "Free Space In Objects", "mtp.free_space_objects",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_storage_description,
            { "Storage Description", "mtp.storage_description",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_volume_identifier,
            { "Volume Identifier", "mtp.volume_identifier",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_group_code,
            { "Free Space In Objects", "mtp.group_code",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_form_flag,
            { "Form flag", "mtp.form_flag",
            FT_UINT8, BASE_HEX, VALS(form_flag_vals),
            0x0, NULL, HFILL }},
        { &hf_maximum_value,
            { "Maximum Value", "mtp.maximum_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_minimum_value,
            { "Minimum Value", "mtp.minimum_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_step_size,
            { "Step Size", "mtp.step_size",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_number_of_values,
            { "NumberOfValues", "mtp.number_of_values",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_supported_value,
            { "SupportedValue", "mtp.supported_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_date_time,
            { "DateTime", "mtp.date_time",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_length,
            { "Length", "mtp.length",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_regexp,
            { "RegExp", "mtp.regexp",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_max_length,
            { "MaxLength", "mtp.max_length",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_object_compressed_size,
            { "Object Compressed Size", "mtp.object_compressed_size",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_thumb_format,
            { "Thumb Format", "mtp.thumb_format",
            FT_UINT16, BASE_HEX, VALS(object_format_vals),
            0x0, NULL, HFILL }},
        { &hf_thumb_compressed_size,
            { "Thumb Compressed Size", "mtp.thumb_compressed_size",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_thumb_pix_width,
            { "Thumb Pix Width", "mtp.thumb_fix_width",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_thumb_pix_height,
            { "Thumb Pix Height", "mtp.thumb_pix_height",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_image_pix_height,
            { "Image Pix Heigth", "mtp.image_pix_heigth",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_image_pix_width,
            { "Image Pix Width", "mtp.image_pix_width",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_image_bit_depth,
            { "Image Bit Depth", "mtp.image_bit_depth",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_parent_object,
            { "Parent Object", "mtp.parent_object",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_association_type,
            { "Association Type", "mtp.association_type",
            FT_UINT16, BASE_HEX, VALS(association_type_vals),
            0x0, NULL, HFILL }},
        { &hf_association_desc,
            { "Association Description", "mtp.association_desc",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
        { &hf_sequence_number,
            { "Sequence Number", "mtp.sequence_number",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_filename,
            { "Filename", "mtp.filename",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_date_created,
            { "Date Created", "mtp.date_created",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_date_modified,
            { "Date Modified", "mtp.date_modified",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_keywords,
            { "Keywords", "mtp.keywords",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_number_of_elements,
            { "NumberOfElements", "mtp.number_of_elements",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_value,
            { "Value", "mtp.value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_value_str,
            { "Value", "mtp.value",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_object_binary_data,
            { "Object Binary Data", "mtp.object_binary_data",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_thumbnail_data,
            { "Thumbnail Data", "mtp.thumbnail_data",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_device_prop_value,
            { "DeviceProp value", "mtp.device_prop_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_object_prop_value,
            { "ObjectProp value", "mtp.object_prop_value",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
        { &hf_num_objects,
            { "NumObjects", "mtp.num_objects",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_bytes_sent,
            { "Actual number of bytes sent", "mtp.bytes_sent",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_failed_property,
            { "Index of failed property", "mtp.failed_property",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_n_interdependencies,
            { "Number of Interdependencies", "mtp.n_interdependecies",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
        { &hf_n_prop_descs,
            { "Number of prop Descs", "mtp.n_prop_descs",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},


    };

    static gint *ett[] = {
        &ett_mtp,
        &ett_mtp_parameters,
        &ett_mtp_array,
        &ett_mtp_dev_info,
        &ett_mtp_prop_desc,
        &ett_mtp_storage_info,
        &ett_mtp_object_info,
        &ett_mtp_dev_prop_desc,
        &ett_mtp_object_prop_list,
        &ett_element,
    };


    proto_register_field_array(proto_mtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mtp(void)
{
    heur_dissector_add("usb.bulk", heur_dissect_mtp,
                       "MTP USB bulk endpoint",
                       "mtp_usb_bulk", proto_mtp,
                       HEURISTIC_ENABLE);
    heur_dissector_add("usb.interrupt", heur_dissect_mtp,
                       "MTP USB interrupt endpoint",
                       "mtp_usb_interrupt", proto_mtp,
                       HEURISTIC_ENABLE);
}
