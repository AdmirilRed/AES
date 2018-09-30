from concurrent.futures.thread import ThreadPoolExecutor
import threading
import os


class AES():

    S_BOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
             0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
             0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
             0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
             0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
             0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
             0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
             0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
             0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
             0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
             0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
             0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
             0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
             0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
             0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
             0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

    R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    MUL_2 = [0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
             0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
             0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
             0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
             0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
             0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
             0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
             0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
             0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
             0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
             0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
             0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
             0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
             0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
             0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
             0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5]

    MUL_3 = [0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
             0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
             0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
             0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
             0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
             0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
             0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
             0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
             0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
             0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
             0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
             0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
             0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
             0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
             0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
             0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a]

    MUL_9 = [0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
             0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
             0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
             0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
             0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
             0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
             0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
             0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
             0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
             0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
             0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
             0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
             0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
             0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
             0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
             0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46]

    MUL_11 = [0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
              0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
              0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
              0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
              0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
              0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
              0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
              0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
              0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
              0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
              0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
              0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
              0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
              0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
              0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
              0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3]

    MUL_13 = [0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
              0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
              0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
              0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
              0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
              0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
              0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
              0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
              0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
              0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
              0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
              0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
              0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
              0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
              0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
              0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97]

    MUL_14 = [0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
              0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
              0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
              0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
              0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
              0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
              0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
              0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
              0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
              0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
              0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
              0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
              0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
              0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
              0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
              0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d]

    def __init__(self, plaintextFile, cyphertextFile,
                 keyFile, keyLength):
        self.plaintextFile = plaintextFile
        self.cyphertextFile = cyphertextFile
        self.keyFile = keyFile
        self.key = AES.Key(keyFile, keyLength)
        self.threadSemaphore = threading.Semaphore(0)
        self.threadQueue = []
        self.doneQueueing = 0

    def __str__(self):
        result = 'Plaintext: \"%s\" ' % self.plaintextFile
        result += 'Cyphertext: \"%s\" ' % self.cyphertextFile
        result += 'Key: \"%s\"' % self.keyFile
        return result

    def encrypt(self):  # INCREASE NUMBER OF WORKERS WHEN DONE DEBUGGING!!!!
        with ThreadPoolExecutor(max_workers=3) as executor:
            executor.submit(self.writeBlocks, self.cyphertextFile)
            with open(self.plaintextFile, 'rb') as f:
                cont = f.read(1)
                while cont:
                    f.seek(-1, 1)
                    block = AES.Block(f)
                    thread = executor.submit(self.encryptBlock, block)
                    self.threadQueue.append(thread)
                    cont = f.read(1)
                    if(not cont):
                        self.doneQueueing = 1
                    self.threadSemaphore.release()

    def writeBlocks(self, filename):
        blockSize = AES.Block.NUM_COLS * AES.Block.NUM_ROWS
        with open(filename, 'wb') as f:
            while self.doneQueueing == 0 or len(self.threadQueue) != 0:
                self.threadSemaphore.acquire()
                thread = self.threadQueue.pop(0)
                block = thread.result()
                block.resetPointer()
                index = 0
                for i in range(int(blockSize/2)):
                    val1 = block.getNext() << 8
                    val2 = block.getNext()
                    key = (val1 + val2).to_bytes(2, byteorder='big')
                    f.write(key)

    def encryptBlock(self, block):
        print('Original Block:')
        print(block)
        roundNum = 0
        block = self.addRoundKey(block, roundNum)
        roundNum += 1
        while roundNum <= self.key.numRounds:
            block = self.subBytes(block)
            block = self.shiftRows(block)
            if(roundNum + 1 <= self.key.numRounds):
                block = self.mixColumns(block)
            block = self.addRoundKey(block, roundNum)
            roundNum += 1
        print('Encrypted Block:')
        print(block)
        return block

    def addRoundKey(self, block, roundNum):
        roundKey = self.key.rounds[roundNum]
        for c in range(AES.Block.NUM_COLS):
            keyWord = roundKey.getColumn(c)
            blockWord = block.getColumn(c)
            AES.Block.xorWords(blockWord, keyWord)
            block.setColumn(c, blockWord)
        return block

    def subBytes(self, block):
        for c in range(AES.Block.NUM_COLS):
            word = block.getColumn(c)
            AES.substituteWord(word)
            block.setColumn(c, word)
        return block

    def shiftRows(self, block):
        for r in range(AES.Block.NUM_ROWS):
            row = block.getRow(r)
            row.rotate(r)
            block.setRow(r, row)
        return block

    def mixColumns(self, block):
        result = AES.Block(None)
        for c in range(AES.Block.NUM_COLS):
            arg1 = AES.MUL_2[block.state[0][c]]
            arg2 = AES.MUL_3[block.state[1][c]]
            arg3 = block.state[2][c]
            arg4 = block.state[3][c]
            newValue = arg1 ^ arg2 ^ arg3 ^ arg4
            result.state[0][c] = newValue
        for c in range(AES.Block.NUM_COLS):
            arg1 = block.state[0][c]
            arg2 = AES.MUL_2[block.state[1][c]]
            arg3 = AES.MUL_3[block.state[2][c]]
            arg4 = block.state[3][c]
            newValue = arg1 ^ arg2 ^ arg3 ^ arg4
            result.state[1][c] = newValue
        for c in range(AES.Block.NUM_COLS):
            arg1 = block.state[0][c]
            arg2 = block.state[1][c]
            arg3 = AES.MUL_2[block.state[2][c]]
            arg4 = AES.MUL_3[block.state[3][c]]
            newValue = arg1 ^ arg2 ^ arg3 ^ arg4
            result.state[2][c] = newValue
        for c in range(AES.Block.NUM_COLS):
            arg1 = AES.MUL_3[block.state[0][c]]
            arg2 = block.state[1][c]
            arg3 = block.state[2][c]
            arg4 = AES.MUL_2[block.state[3][c]]
            newValue = arg1 ^ arg2 ^ arg3 ^ arg4
            result.state[3][c] = newValue
        return result

    def decrypt(self):
        print()

    @staticmethod
    def determineRounds(keyLength):
        if(keyLength == 128):
            rounds = 10
        elif(keyLength == 256):
            rounds = 14
        else:
            sys.exit('Unsupported key length.')
        return rounds

    @staticmethod
    def formatByte(byte):
        return "0x%02X " % byte

    @staticmethod
    def substituteByte(byte):
        return AES.S_BOX[byte]

    @staticmethod
    def substituteWord(word):
        for i in range(AES.Block.NUM_ROWS):
            byte = word.data[i]
            word.data[i] = AES.substituteByte(byte)
        return word

    @staticmethod
    def generateKeyfile(filename, values, keyLength):
        with open(filename, 'wb') as f:
            if(keyLength == 128):
                numBytes = 16
            elif(keyLength == 256):
                numBytes = 32
            else:
                sys.exit('Unsupported keylength.')
            if(values is not None):
                index = 0
                while index < len(values):
                    val1 = values[index] << 8
                    val2 = values[index + 1]
                    key = (val1 + val2).to_bytes(2, byteorder='big')
                    f.write(key)
                    index += 2
            else:
                for i in range(numBytes):
                    key = os.urandom(1)
                    f.write(key)
        return filename

    @staticmethod
    def generatePlainfile(filename, values):
        with open(filename, 'wb') as f:
            numBytes = 16
            if(values is not None):
                index = 0
                while index < len(values):
                    val1 = values[index] << 8
                    val2 = values[index + 1]
                    data = (val1 + val2).to_bytes(2, byteorder='big')
                    f.write(data)
                    index += 2
            else:
                for i in range(numBytes):
                    data = os.urandom(1)
                    f.write(data)
        return filename

    class Block():

        NUM_ROWS = 4
        NUM_COLS = 4

        def __init__(self, openedFile):
            self.currentRow = 0
            self.currentCol = 0
            self.state = []
            for r in range(AES.Block.NUM_ROWS):
                self.state.append([])
                for c in range(AES.Block.NUM_COLS):
                    self.state[r].append(0x00)
            if(openedFile is not None):
                for i in range(AES.Block.NUM_ROWS * AES.Block.NUM_COLS):
                    self.setNext(ord(openedFile.read(1)))
                self.resetPointer()

        def __str__(self):
            result = ''
            for r in range(AES.Block.NUM_ROWS):
                for c in range(AES.Block.NUM_COLS):
                    result += AES.formatByte(self.state[r][c])
                result += '\n'
            return result

        def getColumn(self, index):
            return AES.Block.Column(self.state, index)

        def setColumn(self, index, word):
            for r in range(AES.Block.NUM_ROWS):
                self.state[r][index] = word.data[r]

        def getRow(self, index):
            return AES.Block.Row(self.state, index)

        def setRow(self, index, row):
            for c in range(AES.Block.NUM_COLS):
                self.state[index][c] = row.data[c]

        def getNext(self):
            row = self.currentRow
            col = self.currentCol
            if(row == -1 and col == -1):
                return None
            result = self.state[row][col]
            if(row == AES.Block.NUM_ROWS - 1):
                if(col == AES.Block.NUM_COLS - 1):
                    row = -1
                    col = -1
                else:
                    row = 0
                    col += 1
            else:
                row += 1
            self.currentRow = row
            self.currentCol = col
            return result

        def setNext(self, value):
            row = self.currentRow
            col = self.currentCol
            if(row == -1 and col == -1):
                return None
            self.state[row][col] = value
            if(row == AES.Block.NUM_ROWS - 1):
                if(col == AES.Block.NUM_COLS - 1):
                    row = -1
                    col = -1
                else:
                    row = 0
                    col += 1
            else:
                row += 1
            self.currentRow = row
            self.currentCol = col

        def resetPointer(self):
            self.currentRow = 0
            self.currentCol = 0

        @staticmethod
        def xorWords(word1, word2):
            for r in range(AES.Block.NUM_ROWS):
                result = word1.data[r] ^ word2.data[r]
                word1.data[r] = result

        class Column():

            def __init__(self, state, index):
                self.data = []
                for r in range(AES.Block.NUM_ROWS):
                    self.data.append(state[r][index])

            def __str__(self):
                result = ''
                for r in range(AES.Block.NUM_ROWS):
                    result += '0x%02X\n' % self.data[r]
                return result

            def rotate(self, n):
                for i in range(n):
                    temp = self.data.pop(0)
                    self.data.append(temp)

        class Row():

            def __init__(self, state, index):
                self.data = []
                for c in range(AES.Block.NUM_COLS):
                    self.data.append(state[index][c])

            def __str__(self):
                result = ''
                for c in range(AES.Block.NUM_COLS):
                    result += AES.formatByte(self.data[c])
                return result

            def rotate(self, n):
                for i in range(n):
                    temp = self.data.pop(0)
                    self.data.append(temp)

    class Key():

        def __init__(self, keyFile, keyLength):
            self.numRounds = AES.determineRounds(keyLength)
            self.keyLength = keyLength
            self.rounds = []
            mult = 1
            with open(keyFile, 'rb') as f:
                self.rounds.append(AES.Block(f))
                if(keyLength == 256):
                    self.rounds.append(AES.Block(f))
                    mult = 2
            previousWord = self.rounds[len(self.rounds) - 1].getColumn(
                AES.Block.NUM_COLS - 1)
            wordNum = len(self.rounds) * AES.Block.NUM_COLS
            nk = wordNum
            for roundIndex in range(len(self.rounds), self.numRounds + 1):
                self.rounds.append(AES.Block(None))
                for columnIndex in range(AES.Block.NUM_COLS):
                    currentWord = previousWord
                    if(wordNum % nk == 0):
                        currentWord.rotate(1)
                    if(wordNum % AES.Block.NUM_COLS == 0):
                        AES.substituteWord(currentWord)
                    if(wordNum % nk == 0):
                        rconVal = AES.R_CON[int(wordNum/nk)]
                        currentWord.data[0] = currentWord.data[0] ^ rconVal
                    trailingWord = self.rounds[roundIndex - mult].getColumn(
                        columnIndex)
                    for i in range(AES.Block.NUM_ROWS):
                        currentWord.data[i] = currentWord.data[i] ^ trailingWord.data[i]
                    self.rounds[roundIndex].setColumn(columnIndex, currentWord)
                    previousWord = currentWord
                    wordNum += 1

        def __str__(self):
            result = ''
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[BEGIN KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            result = AES.Key.concatRowDelimiter(result, '-')
            for keyRound in self.rounds:
                result += str(keyRound)
                result = AES.Key.concatRowDelimiter(result, '-')
            result = AES.Key.concatRowDelimiter(result, '=')
            result += '[END KEY]\n'
            result = AES.Key.concatRowDelimiter(result, '=')
            return result

        @staticmethod
        def concatRowDelimiter(str, char):
            numCols = (AES.Block.NUM_COLS * 4) + AES.Block.NUM_COLS - 1
            for c in range(numCols):
                str += char
            str += '\n'
            return str


def main():
    key_128 = [0x2b, 0x7e, 0x15, 0x16,
               0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88,
               0x09, 0xcf, 0x4f, 0x3c]

    key_256 = [0x60, 0x3d, 0xeb, 0x10,
               0x15, 0xca, 0x71, 0xbe,
               0x2b, 0x73, 0xae, 0xf0,
               0x85, 0x7d, 0x77, 0x81,
               0x1f, 0x35, 0x2c, 0x07,
               0x3b, 0x61, 0x08, 0xd7,
               0x2d, 0x98, 0x10, 0xa3,
               0x09, 0x14, 0xdf, 0xf4]

    plain_values = [0x32, 0x43, 0xf6, 0xa8,
                    0x88, 0x5a, 0x30, 0x8d,
                    0x31, 0x31, 0x98, 0xa2,
                    0xe0, 0x37, 0x07, 0x34]

    key_values = key_256
    keySize = len(key_values) * 8
    keyFile = AES.generateKeyfile('key_test.key', key_values, keySize)
    plainFile = AES.generatePlainfile('plain_test.txt', plain_values)
    cypherFile = 'cypher_test.aes'
    instance = AES(plainFile, cypherFile, keyFile, keySize)
    print(instance)
    print(instance.key)
    instance.encrypt()

if __name__ == '__main__':
    main()
