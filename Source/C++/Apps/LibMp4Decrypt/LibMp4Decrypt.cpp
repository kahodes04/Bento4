/*****************************************************************
|
|    AP4 - MP4 Decrypter
|
|    Copyright 2002-2014 Axiomatic Systems, LLC
|
|
|    This file is part of Bento4/AP4 (MP4 Atom Processing Library).
|
|    Unless you have obtained Bento4 under a difference license,
|    this version of Bento4 is Bento4|GPL.
|    Bento4|GPL is free software; you can redistribute it and/or modify
|    it under the terms of the GNU General Public License as published by
|    the Free Software Foundation; either version 2, or (at your option)
|    any later version.
|
|    Bento4|GPL is distributed in the hope that it will be useful,
|    but WITHOUT ANY WARRANTY; without even the implied warranty of
|    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|    GNU General Public License for more details.
|
|    You should have received a copy of the GNU General Public License
|    along with Bento4|GPL; see the file COPYING.  If not, write to the
|    Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
|    02111-1307, USA.
|
 ****************************************************************/

/*----------------------------------------------------------------------
|   includes
+---------------------------------------------------------------------*/
#include "pch.h"


/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
#define BANNER "MP4 Decrypter - Version 1.4\n"\
               "(Bento4 Version " AP4_VERSION_STRING ")\n"\
               "(c) 2002-2015 Axiomatic Systems, LLC"
 
/*----------------------------------------------------------------------
|   PrintUsageAndExit
+---------------------------------------------------------------------*/
static void
PrintUsageAndExit()
{
    fprintf(stderr, 
            BANNER 
            "\n\n"
            "usage: mp4decrypt [options] <input> <output>\n"
            "Options are:\n"
            "  --show-progress : show progress details\n"
            "  --key <id>:<k>\n"
            "      <id> is either a track ID in decimal or a 128-bit KID in hex,\n"
            "      <k> is a 128-bit key in hex\n"
            "      (several --key options can be used, one for each track or KID)\n"
            "      note: for dcf files, use 1 as the track index\n"
            "      note: for Marlin IPMP/ACGK, use 0 as the track ID\n"
            "      note: KIDs are only applicable to some encryption methods like MPEG-CENC\n"
            "  --fragments-info <filename>\n"
            "      Decrypt the fragments read from <input>, with track info read\n"
            "      from <filename>.\n"
            );
    exit(1);
}

/*----------------------------------------------------------------------
|   ProgressListener
+---------------------------------------------------------------------*/
class ProgressListener : public AP4_Processor::ProgressListener
{
public:
    AP4_Result OnProgress(unsigned int step, unsigned int total);
};

AP4_Result
ProgressListener::OnProgress(unsigned int step, unsigned int total)
{
    printf("\r%d/%d", step, total);
    return AP4_SUCCESS;
}

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

EXTERN_DLL_EXPORT unsigned char* DecryptMP4Content(const unsigned char* inputData,
    char* decryptionKey,
    AP4_Size inputSize,
    unsigned long long* outputSize,
    bool* success,
    char** errorMessagePtr)
{
    // create a key map object to hold keys
    AP4_ProtectionKeyMap key_map;

    // parse key
    if (decryptionKey == NULL) {
        *success = false;
        return nullptr;
    }

    char* keyid_text = NULL;
    char* key_text = NULL;
    if (AP4_SplitArgs(decryptionKey, keyid_text, key_text)) {
        *success = false;
        return nullptr;
    }

    unsigned char key[16];
    unsigned int  track_id = 0;
    unsigned char kid[16];
    if (strlen(keyid_text) == 32) {
        if (AP4_ParseHex(keyid_text, kid, 16)) {
            return nullptr;
        }
    }
    else {
        track_id = (unsigned int)strtoul(keyid_text, NULL, 10);
        if (track_id == 0) {
            return nullptr;
        }
    }
    if (AP4_ParseHex(key_text, key, 16)) {
        return nullptr;
    }
    // set the key in the map
    if (track_id) {
        key_map.SetKey(track_id, key, 16);
    }
    else {
        key_map.SetKeyForKid(kid, key, 16);
    }



    // create the input stream
    AP4_Result result;

    AP4_MemoryByteStream* input = new AP4_MemoryByteStream(inputData, inputSize);
    AP4_MemoryByteStream* output = new AP4_MemoryByteStream();


    // create the decrypting processor
    AP4_Processor* processor = NULL;
    AP4_File* input_file = new AP4_File(*input);
    AP4_FtypAtom* ftyp = input_file->GetFileType();
    if (ftyp) {
        if (ftyp->GetMajorBrand() == AP4_OMA_DCF_BRAND_ODCF || ftyp->HasCompatibleBrand(AP4_OMA_DCF_BRAND_ODCF)) {
            processor = new AP4_OmaDcfDecryptingProcessor(&key_map);
        }
        else if (ftyp->GetMajorBrand() == AP4_MARLIN_BRAND_MGSV || ftyp->HasCompatibleBrand(AP4_MARLIN_BRAND_MGSV)) {
            processor = new AP4_MarlinIpmpDecryptingProcessor(&key_map);
        }
        else if (ftyp->GetMajorBrand() == AP4_PIFF_BRAND || ftyp->HasCompatibleBrand(AP4_PIFF_BRAND)) {
            processor = new AP4_CencDecryptingProcessor(&key_map);
        }
    }
    if (processor == NULL) {
        // no ftyp, look at the sample description of the tracks first
        AP4_Movie* movie = input_file->GetMovie();
        if (movie) {
            AP4_List<AP4_Track>& tracks = movie->GetTracks();
            for (unsigned int i = 0; i < tracks.ItemCount(); i++) {
                AP4_Track* track = NULL;
                tracks.Get(i, track);
                if (track) {
                    AP4_SampleDescription* sdesc = track->GetSampleDescription(0);
                    if (sdesc && sdesc->GetType() == AP4_SampleDescription::TYPE_PROTECTED) {
                        AP4_ProtectedSampleDescription* psdesc = AP4_DYNAMIC_CAST(AP4_ProtectedSampleDescription, sdesc);
                        if (psdesc) {
                            if (psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENC ||
                                psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBC1 ||
                                psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CENS ||
                                psdesc->GetSchemeType() == AP4_PROTECTION_SCHEME_TYPE_CBCS) {
                                processor = new AP4_CencDecryptingProcessor(&key_map);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // by default, try a standard decrypting processor
    if (processor == NULL) {
        processor = new AP4_StandardDecryptingProcessor(&key_map);
    }

    delete input_file;
    input_file = NULL;

    input->Seek(0);


    // process/decrypt the file
    ProgressListener listener;
    result = processor->Process(*input, *output, NULL);
    if (AP4_FAILED(result)) {
        *success = false;
        delete processor;
        input->Release();
        output->Release();
        return nullptr;
    }

    output->Seek(0);
    AP4_LargeSize size = 0;
    output->GetSize(size);
    AP4_Size bytesRead = 0;
    unsigned char* outBuffer = new unsigned char[size];
    output->ReadPartial(outBuffer, (AP4_Size)size, bytesRead);
    *outputSize = size;

    *success = true;

    // Cleanup
    delete processor;
    if (input) {
        input->Release();
    }
    if (output) {
        output->Release();
    }
    return outBuffer;
}

// free memory

EXTERN_DLL_EXPORT void FreeMemory(char* memory) {
    if (memory != NULL) {
        free(memory);
        memory = NULL;
    }
}
