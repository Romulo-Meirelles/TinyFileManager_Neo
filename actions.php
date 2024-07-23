<?php
/**
 * Mr. Meirelles | Tiny File Manager V3.0.0
 * @author Rômulo Meirelles Programmer
 * @email romulomeirelles@hotmail.com
 * @github https://github.com/Romulo-Meirelles/TinyFileManager_Neo
 * @link https://github.com/Romulo-Meirelles
 */
 
// Handle all AJAX Request
if ((isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']]) || !FM_USE_AUTH) && isset($_POST['ajax'], $_POST['token']) && !FM_READONLY) {
    if(!verifyToken($_POST['token'])) {
        header('HTTP/1.0 401 Unauthorized');
        die("Invalid Token.");
    }

    //search : get list of files from the current folder
    if(isset($_POST['type']) && $_POST['type']=="search") {
        $dir = $_POST['path'] == "." ? '': $_POST['path'];
        $response = scan(fm_clean_path($dir), $_POST['content']);
        echo json_encode($response);
        exit();
    }

    // save editor file
    if (isset($_POST['type']) && $_POST['type'] == "save") {
        // get current path
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        // check path
        if (!is_dir($path)) {
            fm_redirect(FM_SELF_URL . '?p=');
        }
        $file = $_GET['edit'];
        $file = fm_clean_path($file);
        $file = str_replace('/', '', $file);
        if ($file == '' || !is_file($path . '/' . $file)) {
            fm_set_msg(lng('File not found'), 'error');
            $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        }
        header('X-XSS-Protection:0');
        $file_path = $path . '/' . $file;

        $writedata = $_POST['content'];
        $fd = fopen($file_path, "w");
        $write_results = @fwrite($fd, $writedata);
        fclose($fd);
        if ($write_results === false){
            header("HTTP/1.1 500 Internal Server Error");
            die("Could Not Write File! - Check Permissions / Ownership");
        }
        die(true);
    }

    // backup files
    if (isset($_POST['type']) && $_POST['type'] == "backup" && !empty($_POST['file'])) {
        $fileName = fm_clean_path($_POST['file']);
        $fullPath = FM_ROOT_PATH . '/';
        if (!empty($_POST['path'])) {
            $relativeDirPath = fm_clean_path($_POST['path']);
            $fullPath .= "{$relativeDirPath}/";
        }
        $date = date("dMy-His");
        $newFileName = "{$fileName}-{$date}.bak";
        $fullyQualifiedFileName = $fullPath . $fileName;
        try {
            if (!file_exists($fullyQualifiedFileName)) {
                throw new Exception("File {$fileName} not found");
            }
            if (copy($fullyQualifiedFileName, $fullPath . $newFileName)) {
                echo "Backup {$newFileName} created";
            } else {
                throw new Exception("Could not copy file {$fileName}");
            }
        } catch (Exception $e) {
            echo $e->getMessage();
        }
    }

    // Save Config
    if (isset($_POST['type']) && $_POST['type'] == "settings") {
        global $cfg, $lang, $report_errors, $show_hidden_files, $lang_list, $hide_Cols, $theme;
        $newLng = $_POST['js-language'];
        fm_get_translations([]);
        if (!array_key_exists($newLng, $lang_list)) {
            $newLng = 'en';
        }

        $erp = isset($_POST['js-error-report']) && $_POST['js-error-report'] == "true" ? true : false;
        $shf = isset($_POST['js-show-hidden']) && $_POST['js-show-hidden'] == "true" ? true : false;
        $hco = isset($_POST['js-hide-cols']) && $_POST['js-hide-cols'] == "true" ? true : false;
        $te3 = $_POST['js-theme-3'];

        if ($cfg->data['lang'] != $newLng) {
            $cfg->data['lang'] = $newLng;
            $lang = $newLng;
        }
        if ($cfg->data['error_reporting'] != $erp) {
            $cfg->data['error_reporting'] = $erp;
            $report_errors = $erp;
        }
        if ($cfg->data['show_hidden'] != $shf) {
            $cfg->data['show_hidden'] = $shf;
            $show_hidden_files = $shf;
        }
        if ($cfg->data['show_hidden'] != $shf) {
            $cfg->data['show_hidden'] = $shf;
            $show_hidden_files = $shf;
        }
        if ($cfg->data['hide_Cols'] != $hco) {
            $cfg->data['hide_Cols'] = $hco;
            $hide_Cols = $hco;
        }
        if ($cfg->data['theme'] != $te3) {
            $cfg->data['theme'] = $te3;
            $theme = $te3;
        }
        $cfg->save();
        echo true;
    }

    // new password hash
    if (isset($_POST['type']) && $_POST['type'] == "pwdhash") {
        $res = isset($_POST['inputPassword2']) && !empty($_POST['inputPassword2']) ? password_hash($_POST['inputPassword2'], PASSWORD_DEFAULT) : '';
        echo $res;
    }

    //upload using url
    if(isset($_POST['type']) && $_POST['type'] == "upload" && !empty($_REQUEST["uploadurl"])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }

         function event_callback ($message) {
            global $callback;
            echo json_encode($message);
        }

        function get_file_path () {
            global $path, $fileinfo, $temp_file;
            return $path."/".basename($fileinfo->name);
        }

        $url = !empty($_REQUEST["uploadurl"]) && preg_match("|^http(s)?://.+$|", stripslashes($_REQUEST["uploadurl"])) ? stripslashes($_REQUEST["uploadurl"]) : null;

        //prevent 127.* domain and known ports
        $domain = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);
        $knownPorts = [22, 23, 25, 3306];

        if (preg_match("/^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$/i", $domain) || in_array($port, $knownPorts)) {
            $err = array("message" => "URL is not allowed");
            event_callback(array("fail" => $err));
            exit();
        }

        $use_curl = false;
        $temp_file = tempnam(sys_get_temp_dir(), "upload-");
        $fileinfo = new stdClass();
        $fileinfo->name = trim(urldecode(basename($url)), ".\x00..\x20");

        $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
        $ext = strtolower(pathinfo($fileinfo->name, PATHINFO_EXTENSION));
        $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

        $err = false;

        if(!$isFileAllowed) {
            $err = array("message" => "File extension is not allowed");
            event_callback(array("fail" => $err));
            exit();
        }

        if (!$url) {
            $success = false;
        } else if ($use_curl) {
            @$fp = fopen($temp_file, "w");
            @$ch = curl_init($url);
            curl_setopt($ch, CURLOPT_NOPROGRESS, false );
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            @$success = curl_exec($ch);
            $curl_info = curl_getinfo($ch);
            if (!$success) {
                $err = array("message" => curl_error($ch));
            }
            @curl_close($ch);
            fclose($fp);
            $fileinfo->size = $curl_info["size_download"];
            $fileinfo->type = $curl_info["content_type"];
        } else {
            $ctx = stream_context_create();
            @$success = copy($url, $temp_file, $ctx);
            if (!$success) {
                $err = error_get_last();
            }
        }

        if ($success) {
            $success = rename($temp_file, strtok(get_file_path(), '?'));
        }

        if ($success) {
            event_callback(array("done" => $fileinfo));
        } else {
            unlink($temp_file);
            if (!$err) {
                $err = array("message" => "Invalid url parameter");
            }
            event_callback(array("fail" => $err));
        }
    }
    exit();
}

// Delete file / folder
if (isset($_GET['del'], $_POST['token']) && !FM_READONLY) {
    $del = str_replace( '/', '', fm_clean_path( $_GET['del'] ) );
    if ($del != '' && $del != '..' && $del != '.' && verifyToken($_POST['token'])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        $is_dir = is_dir($path . '/' . $del);
        if (fm_rdelete($path . '/' . $del)) {
            $msg = $is_dir ? lng('Folder').' <b>%s</b> '.lng('Deleted') : lng('File').' <b>%s</b> '.lng('Deleted');
            fm_set_msg(sprintf($msg, fm_enc($del)));
        } else {
            $msg = $is_dir ? lng('Folder').' <b>%s</b> '.lng('not deleted') : lng('File').' <b>%s</b> '.lng('not deleted');
            fm_set_msg(sprintf($msg, fm_enc($del)), 'error');
        }
    } else {
        fm_set_msg(lng('Invalid file or folder name'), 'error');
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Create a new file/folder
if (isset($_POST['newfilename'], $_POST['newfile'], $_POST['token']) && !FM_READONLY) {
    $type = urldecode($_POST['newfile']);
    $new = str_replace( '/', '', fm_clean_path( strip_tags( $_POST['newfilename'] ) ) );
    if (fm_isvalid_filename($new) && $new != '' && $new != '..' && $new != '.' && verifyToken($_POST['token'])) {
        $path = FM_ROOT_PATH;
        if (FM_PATH != '') {
            $path .= '/' . FM_PATH;
        }
        if ($type == "file") {
            if (!file_exists($path . '/' . $new)) {
                if(fm_is_valid_ext($new)) {
                    @fopen($path . '/' . $new, 'w') or die('Cannot open file:  ' . $new);
                    fm_set_msg(sprintf(lng('File').' <b>%s</b> '.lng('Created'), fm_enc($new)));
                } else {
                    fm_set_msg(lng('File extension is not allowed'), 'error');
                }
            } else {
                fm_set_msg(sprintf(lng('File').' <b>%s</b> '.lng('already exists'), fm_enc($new)), 'alert');
            }
        } else {
            if (fm_mkdir($path . '/' . $new, false) === true) {
                fm_set_msg(sprintf(lng('Folder').' <b>%s</b> '.lng('Created'), $new));
            } elseif (fm_mkdir($path . '/' . $new, false) === $path . '/' . $new) {
                fm_set_msg(sprintf(lng('Folder').' <b>%s</b> '.lng('already exists'), fm_enc($new)), 'alert');
            } else {
                fm_set_msg(sprintf(lng('Folder').' <b>%s</b> '.lng('not created'), fm_enc($new)), 'error');
            }
        }
    } else {
        fm_set_msg(lng('Invalid characters in file or folder name'), 'error');
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Copy folder / file
if (isset($_GET['copy'], $_GET['finish']) && !FM_READONLY) {
    // from
    $copy = urldecode($_GET['copy']);
    $copy = fm_clean_path($copy);
    // empty path
    if ($copy == '') {
        fm_set_msg(lng('Source path not defined'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
    // abs path from
    $from = FM_ROOT_PATH . '/' . $copy;
    // abs path to
    $dest = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $dest .= '/' . FM_PATH;
    }
    $dest .= '/' . basename($from);
    // move?
    $move = isset($_GET['move']);
    $move = fm_clean_path(urldecode($move));
    // copy/move/duplicate
    if ($from != $dest) {
        $msg_from = trim(FM_PATH . '/' . basename($from), '/');
        if ($move) { // Move and to != from so just perform move
            $rename = fm_rename($from, $dest);
            if ($rename) {
                fm_set_msg(sprintf(lng('Moved from').' <b>%s</b> '.lng('to').' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
            } elseif ($rename === null) {
                fm_set_msg(lng('File or folder with this path already exists'), 'alert');
            } else {
                fm_set_msg(sprintf(lng('Error while moving from').' <b>%s</b> '.lng('to').' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
            }
        } else { // Not move and to != from so copy with original name
            if (fm_rcopy($from, $dest)) {
                fm_set_msg(sprintf(lng('Copied from').' <b>%s</b> '.lng('to').' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
            } else {
                fm_set_msg(sprintf(lng('Error while copying from').' <b>%s</b> '.lng('to').' <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
            }
        }
    } else {
       if (!$move){ //Not move and to = from so duplicate
            $msg_from = trim(FM_PATH . '/' . basename($from), '/');
            $fn_parts = pathinfo($from);
            $extension_suffix = '';
            if(!is_dir($from)){
               $extension_suffix = '.'.$fn_parts['extension'];
            }
            //Create new name for duplicate
            $fn_duplicate = $fn_parts['dirname'].'/'.$fn_parts['filename'].'-'.date('YmdHis').$extension_suffix;
            $loop_count = 0;
            $max_loop = 1000;
            // Check if a file with the duplicate name already exists, if so, make new name (edge case...)
            while(file_exists($fn_duplicate) & $loop_count < $max_loop){
               $fn_parts = pathinfo($fn_duplicate);
               $fn_duplicate = $fn_parts['dirname'].'/'.$fn_parts['filename'].'-copy'.$extension_suffix;
               $loop_count++;
            }
            if (fm_rcopy($from, $fn_duplicate, False)) {
                fm_set_msg(sprintf('Copied from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)));
            } else {
                fm_set_msg(sprintf('Error while copying from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)), 'error');
            }
       }
       else{
           fm_set_msg(lng('Paths must be not equal'), 'alert');
       }
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Mass copy files/ folders
if (isset($_POST['file'], $_POST['copy_to'], $_POST['finish'], $_POST['token']) && !FM_READONLY) {

    if(!verifyToken($_POST['token'])) {
        fm_set_msg(lng('Invalid Token.'), 'error');
    }
    
    // from
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    // to
    $copy_to_path = FM_ROOT_PATH;
    $copy_to = fm_clean_path($_POST['copy_to']);
    if ($copy_to != '') {
        $copy_to_path .= '/' . $copy_to;
    }
    if ($path == $copy_to_path) {
        fm_set_msg(lng('Paths must be not equal'), 'alert');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
    if (!is_dir($copy_to_path)) {
        if (!fm_mkdir($copy_to_path, true)) {
            fm_set_msg('Unable to create destination folder', 'error');
            $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
        }
    }
    // move?
    $move = isset($_POST['move']);
    // copy/move
    $errors = 0;
    $files = $_POST['file'];
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $f = fm_clean_path($f);
                // abs path from
                $from = $path . '/' . $f;
                // abs path to
                $dest = $copy_to_path . '/' . $f;
                // do
                if ($move) {
                    $rename = fm_rename($from, $dest);
                    if ($rename === false) {
                        $errors++;
                    }
                } else {
                    if (!fm_rcopy($from, $dest)) {
                        $errors++;
                    }
                }
            }
        }
        if ($errors == 0) {
            $msg = $move ? 'Selected files and folders moved' : 'Selected files and folders copied';
            fm_set_msg($msg);
        } else {
            $msg = $move ? 'Error while moving items' : 'Error while copying items';
            fm_set_msg($msg, 'error');
        }
    } else {
        fm_set_msg(lng('Nothing selected'), 'alert');
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Rename
if (isset($_POST['rename_from'], $_POST['rename_to'], $_POST['token']) && !FM_READONLY) {
    if(!verifyToken($_POST['token'])) {
        fm_set_msg("Invalid Token.", 'error');
    }
    // old name
    $old = urldecode($_POST['rename_from']);
    $old = fm_clean_path($old);
    $old = str_replace('/', '', $old);
    // new name
    $new = urldecode($_POST['rename_to']);
    $new = fm_clean_path(strip_tags($new));
    $new = str_replace('/', '', $new);
    // path
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    // rename
    if (fm_isvalid_filename($new) && $old != '' && $new != '') {
        if (fm_rename($path . '/' . $old, $path . '/' . $new)) {
            fm_set_msg(sprintf(lng('Renamed from').' <b>%s</b> '. lng('to').' <b>%s</b>', fm_enc($old), fm_enc($new)));
        } else {
            fm_set_msg(sprintf(lng('Error while renaming from').' <b>%s</b> '. lng('to').' <b>%s</b>', fm_enc($old), fm_enc($new)), 'error');
        }
    } else {
        fm_set_msg(lng('Invalid characters in file name'), 'error');
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Download
if (isset($_GET['dl'], $_POST['token'])) {
    if(!verifyToken($_POST['token'])) {
        fm_set_msg("Invalid Token.", 'error');
    }

    $dl = urldecode($_GET['dl']);
    $dl = fm_clean_path($dl);
    $dl = str_replace('/', '', $dl);
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }
    if ($dl != '' && is_file($path . '/' . $dl)) {
        fm_download_file($path . '/' . $dl, $dl, 1024);
        exit;
    } else {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
}

// Upload
if (!empty($_FILES) && !FM_READONLY) {
    if(isset($_POST['token'])) {
        if(!verifyToken($_POST['token'])) {
            $response = array ('status' => 'error','info' => "Invalid Token.");
            echo json_encode($response); exit();
        }
    } else {
        $response = array ('status' => 'error','info' => "Token Missing.");
        echo json_encode($response); exit();
    }

    $chunkIndex = $_POST['dzchunkindex'];
    $chunkTotal = $_POST['dztotalchunkcount'];
    $fullPathInput = fm_clean_path($_REQUEST['fullpath']);

    $f = $_FILES;
    $path = FM_ROOT_PATH;
    $ds = DIRECTORY_SEPARATOR;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $uploads = 0;
    $allowed = (FM_UPLOAD_EXTENSION) ? explode(',', FM_UPLOAD_EXTENSION) : false;
    $response = array (
        'status' => 'error',
        'info'   => 'Oops! Try again'
    );

    $filename = $f['file']['name'];
    $tmp_name = $f['file']['tmp_name'];
    $ext = pathinfo($filename, PATHINFO_FILENAME) != '' ? strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';
    $isFileAllowed = ($allowed) ? in_array($ext, $allowed) : true;

    if(!fm_isvalid_filename($filename) && !fm_isvalid_filename($fullPathInput)) {
        $response = array (
            'status'    => 'error',
            'info'      => "Invalid File name!",
        );
        echo json_encode($response); exit();
    }

    $targetPath = $path . $ds;
    if ( is_writable($targetPath) ) {
        $fullPath = $path . '/' . $fullPathInput;
        $folder = substr($fullPath, 0, strrpos($fullPath, "/"));

        if (!is_dir($folder)) {
            $old = umask(0);
            mkdir($folder, 0777, true);
            umask($old);
        }

        if (empty($f['file']['error']) && !empty($tmp_name) && $tmp_name != 'none' && $isFileAllowed) {
            if ($chunkTotal){
                $out = @fopen("{$fullPath}.part", $chunkIndex == 0 ? "wb" : "ab");
                if ($out) {
                    $in = @fopen($tmp_name, "rb");
                    if ($in) {
                        if (PHP_VERSION_ID < 80009) {
                            // workaround https://bugs.php.net/bug.php?id=81145
                            do {
                                for (;;) {
                                    $buff = fread($in, 4096);
                                    if ($buff === false || $buff === '') {
                                        break;
                                    }
                                    fwrite($out, $buff);
                                }
                            } while (!feof($in));
                        } else {
                            stream_copy_to_stream($in, $out);
                        }
                        $response = array (
                            'status'    => 'success',
                            'info' => "file upload successful"
                        );
                    } else {
                        $response = array (
                        'status'    => 'error',
                        'info' => "failed to open output stream",
                        'errorDetails' => error_get_last()
                        );
                    }
                    @fclose($in);
                    @fclose($out);
                    @unlink($tmp_name);

                    $response = array (
                        'status'    => 'success',
                        'info' => "file upload successful"
                    );
                } else {
                    $response = array (
                        'status'    => 'error',
                        'info' => "failed to open output stream"
                        );
                }

                if ($chunkIndex == $chunkTotal - 1) {
                    if (file_exists ($fullPath)) {
                        $ext_1 = $ext ? '.'.$ext : '';
                        $fullPathTarget = $path . '/' . basename($fullPathInput, $ext_1) .'_'. date('ymdHis'). $ext_1;
                    } else {
                        $fullPathTarget = $fullPath;
                    }
                    rename("{$fullPath}.part", $fullPathTarget);
                }

            } else if (move_uploaded_file($tmp_name, $fullPath)) {
                // Be sure that the file has been uploaded
                if ( file_exists($fullPath) ) {
                    $response = array (
                        'status'    => 'success',
                        'info' => "file upload successful"
                    );
                } else {
                    $response = array (
                        'status' => 'error',
                        'info'   => 'Couldn\'t upload the requested file.'
                    );
                }
            } else {
                $response = array (
                    'status'    => 'error',
                    'info'      => "Error while uploading files. Uploaded files $uploads",
                );
            }
        }
    } else {
        $response = array (
            'status' => 'error',
            'info'   => 'The specified folder for upload isn\'t writeable.'
        );
    }
    // Return the response
    echo json_encode($response);
    exit();
}

// Mass deleting
if (isset($_POST['group'], $_POST['delete'], $_POST['token']) && !FM_READONLY) {

    if(!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
    }

    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $errors = 0;
    $files = $_POST['file'];
    if (is_array($files) && count($files)) {
        foreach ($files as $f) {
            if ($f != '') {
                $new_path = $path . '/' . $f;
                if (!fm_rdelete($new_path)) {
                    $errors++;
                }
            }
        }
        if ($errors == 0) {
            fm_set_msg(lng('Selected files and folder deleted'));
        } else {
            fm_set_msg(lng('Error while deleting items'), 'error');
        }
    } else {
        fm_set_msg(lng('Nothing selected'), 'alert');
    }

    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Pack files zip, tar
if (isset($_POST['group'], $_POST['token']) && (isset($_POST['zip']) || isset($_POST['tar'])) && !FM_READONLY) {

    if(!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
    }

    $path = FM_ROOT_PATH;
    $ext = 'zip';
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    //set pack type
    $ext = isset($_POST['tar']) ? 'tar' : 'zip';

    if (($ext == "zip" && !class_exists('ZipArchive')) || ($ext == "tar" && !class_exists('PharData'))) {
        fm_set_msg(lng('Operations with archives are not available'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    $files = $_POST['file'];
    $sanitized_files = array();

    // clean path
    foreach($files as $file){
        array_push($sanitized_files, fm_clean_path($file));
    }
    
    $files = $sanitized_files;
    
    if (!empty($files)) {
        chdir($path);

        if (count($files) == 1) {
            $one_file = reset($files);
            $one_file = basename($one_file);
            $zipname = $one_file . '_' . date('ymd_His') . '.'.$ext;
        } else {
            $zipname = 'archive_' . date('ymd_His') . '.'.$ext;
        }

        if($ext == 'zip') {
            $zipper = new FM_Zipper();
            $res = $zipper->create($zipname, $files);
        } elseif ($ext == 'tar') {
            $tar = new FM_Zipper_Tar();
            $res = $tar->create($zipname, $files);
        }

        if ($res) {
            fm_set_msg(sprintf(lng('Archive').' <b>%s</b> '.lng('Created'), fm_enc($zipname)));
        } else {
            fm_set_msg(lng('Archive not created'), 'error');
        }
    } else {
        fm_set_msg(lng('Nothing selected'), 'alert');
    }

    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Unpack zip, tar
if (isset($_POST['unzip'], $_POST['token']) && !FM_READONLY) {

    if(!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
    }

    $unzip = urldecode($_POST['unzip']);
    $unzip = fm_clean_path($unzip);
    $unzip = str_replace('/', '', $unzip);
    $isValid = false;

    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    if ($unzip != '' && is_file($path . '/' . $unzip)) {
        $zip_path = $path . '/' . $unzip;
        $ext = pathinfo($zip_path, PATHINFO_EXTENSION);
        $isValid = true;
    } else {
        fm_set_msg(lng('File not found'), 'error');
    }

    if (($ext == "zip" && !class_exists('ZipArchive')) || ($ext == "tar" && !class_exists('PharData'))) {
        fm_set_msg(lng('Operations with archives are not available'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    if ($isValid) {
        //to folder
        $tofolder = '';
        if (isset($_POST['tofolder'])) {
            $tofolder = pathinfo($zip_path, PATHINFO_FILENAME);
            if (fm_mkdir($path . '/' . $tofolder, true)) {
                $path .= '/' . $tofolder;
            }
        }

        if($ext == "zip") {
            $zipper = new FM_Zipper();
            $res = $zipper->unzip($zip_path, $path);
        } elseif ($ext == "tar") {
            try {
                $gzipper = new PharData($zip_path);
                if (@$gzipper->extractTo($path,null, true)) {
                    $res = true;
                } else {
                    $res = false;
                }
            } catch (Exception $e) {
                //TODO:: need to handle the error
                $res = true;
            }
        }

        if ($res) {
            fm_set_msg(lng('Archive unpacked'));
        } else {
            fm_set_msg(lng('Archive not unpacked'), 'error');
        }
    } else {
        fm_set_msg(lng('File not found'), 'error');
    }
    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}

// Change Perms (not for Windows)
if (isset($_POST['chmod'], $_POST['token']) && !FM_READONLY && !FM_IS_WIN) {

    if(!verifyToken($_POST['token'])) {
        fm_set_msg(lng("Invalid Token."), 'error');
    }
    
    $path = FM_ROOT_PATH;
    if (FM_PATH != '') {
        $path .= '/' . FM_PATH;
    }

    $file = $_POST['chmod'];
    $file = fm_clean_path($file);
    $file = str_replace('/', '', $file);
    if ($file == '' || (!is_file($path . '/' . $file) && !is_dir($path . '/' . $file))) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    $mode = 0;
    if (!empty($_POST['ur'])) {
        $mode |= 0400;
    }
    if (!empty($_POST['uw'])) {
        $mode |= 0200;
    }
    if (!empty($_POST['ux'])) {
        $mode |= 0100;
    }
    if (!empty($_POST['gr'])) {
        $mode |= 0040;
    }
    if (!empty($_POST['gw'])) {
        $mode |= 0020;
    }
    if (!empty($_POST['gx'])) {
        $mode |= 0010;
    }
    if (!empty($_POST['or'])) {
        $mode |= 0004;
    }
    if (!empty($_POST['ow'])) {
        $mode |= 0002;
    }
    if (!empty($_POST['ox'])) {
        $mode |= 0001;
    }

    if (@chmod($path . '/' . $file, $mode)) {
        fm_set_msg(lng('Permissions changed'));
    } else {
        fm_set_msg(lng('Permissions not changed'), 'error');
    }

    $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
}


// get current path
$path = FM_ROOT_PATH;
if (FM_PATH != '') {
    $path .= '/' . FM_PATH;
}

// check path
if (!is_dir($path)) {
    fm_redirect(FM_SELF_URL . '?p=');
}

// get parent folder
$parent = fm_get_parent_path(FM_PATH);

$objects = is_readable($path) ? scandir($path) : array();
$folders = array();
$files = array();
$current_path = array_slice(explode("/",$path), -1)[0];



if (is_array($objects) && fm_is_exclude_items($current_path)) {
    foreach ($objects as $file) {
        if ($file == '.' || $file == '..') {
            continue;
        }
        if (!FM_SHOW_HIDDEN && substr($file, 0, 1) === '.') {
            continue;
        }
        $new_path = $path . '/' . $file;
        if (@is_file($new_path) && fm_is_exclude_items($file)) {
            $files[] = $file;
        } elseif (@is_dir($new_path) && $file != '.' && $file != '..' && fm_is_exclude_items($file)) {
            $folders[] = $file;
        }
    }
}

if (!empty($files)) {
    natcasesort($files);
}
if (!empty($folders)) {
    natcasesort($folders);
}

// upload form
if (isset($_GET['upload']) && !FM_READONLY) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    //get the allowed file extensions
    function getUploadExt() {
        $extArr = explode(',', FM_UPLOAD_EXTENSION);
        if(FM_UPLOAD_EXTENSION && $extArr) {
            array_walk($extArr, function(&$x) {$x = ".$x";});
            return implode(',', $extArr);
        }
        return '';
    }
	
   include 'HTML/file-upload.html';
   
    fm_show_footer();
    exit;
}

// copy form POST
if (isset($_POST['copy']) && !FM_READONLY) {
    $copy_files = isset($_POST['file']) ? $_POST['file'] : null;
    if (!is_array($copy_files) || empty($copy_files)) {
        fm_set_msg(lng('Nothing selected'), 'alert');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
	
    include 'HTML/copy-form-post.html';
	
    fm_show_footer();
    exit;
}

// copy form
if (isset($_GET['copy']) && !isset($_GET['finish']) && !FM_READONLY) {
    $copy = $_GET['copy'];
    $copy = fm_clean_path($copy);
    if ($copy == '' || !file_exists(FM_ROOT_PATH . '/' . $copy)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    
	include 'HTML/copy-form.html';
	
    fm_show_footer();
    exit;
}

if (isset($_GET['settings']) && !FM_READONLY) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang, $lang_list;
    
    include 'HTML/settings.html';
   
    fm_show_footer();
    exit;
}

if (isset($_GET['help'])) {
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path
    global $cfg, $lang;
	
	include 'HTML/help.html';
   
    fm_show_footer();
    exit;
}

// file viewer
if (isset($_GET['view'])) {
    $file = $_GET['view'];
    $file = fm_clean_path($file, false);
    $file = str_replace('/', '', $file);
    if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
    $file_path = $path . '/' . $file;

    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_type = fm_get_mime_type($file_path);
    $filesize_raw = fm_get_size($file_path);
    $filesize = fm_get_filesize($filesize_raw);

    $is_zip = false;
    $is_gzip = false;
    $is_image = false;
    $is_audio = false;
    $is_video = false;
    $is_text = false;
    $is_onlineViewer = false;

    $view_title = 'File';
    $filenames = false; // for zip
    $content = ''; // for text
    $online_viewer = strtolower(FM_DOC_VIEWER);

    if($online_viewer && $online_viewer !== 'false' && in_array($ext, fm_get_onlineViewer_exts())){
        $is_onlineViewer = true;
    }
    elseif ($ext == 'zip' || $ext == 'tar') {
        $is_zip = true;
        $view_title = 'Archive';
        $filenames = fm_get_zif_info($file_path, $ext);
    } elseif (in_array($ext, fm_get_image_exts())) {
        $is_image = true;
        $view_title = 'Image';
    } elseif (in_array($ext, fm_get_audio_exts())) {
        $is_audio = true;
        $view_title = 'Audio';
    } elseif (in_array($ext, fm_get_video_exts())) {
        $is_video = true;
        $view_title = 'Video';
    } elseif (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
        $is_text = true;
        $content = file_get_contents($file_path);
    }

     include 'HTML/file-viewer.html';
        fm_show_footer();
    exit;
}

// file editor
if (isset($_GET['edit']) && !FM_READONLY) {
    $file = $_GET['edit'];
    $file = fm_clean_path($file, false);
    $file = str_replace('/', '', $file);
    if ($file == '' || !is_file($path . '/' . $file) || !fm_is_exclude_items($file)) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }
    $editFile = ' : <i><b>'. $file. '</b></i>';
    header('X-XSS-Protection:0');
    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . fm_convert_win((FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file);
    $file_path = $path . '/' . $file;

    // normal editer
    $isNormalEditor = true;
    if (isset($_GET['env'])) {
        if ($_GET['env'] == "ace") {
            $isNormalEditor = false;
        }
    }

    // Save File
    if (isset($_POST['savedata'])) {
        $writedata = $_POST['savedata'];
        $fd = fopen($file_path, "w");
        @fwrite($fd, $writedata);
        fclose($fd);
        fm_set_msg(lng('File Saved Successfully'));
    }

    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_type = fm_get_mime_type($file_path);
    $filesize = filesize($file_path);
    $is_text = false;
    $content = ''; // for text

    if (in_array($ext, fm_get_text_exts()) || substr($mime_type, 0, 4) == 'text' || in_array($mime_type, fm_get_text_mimes())) {
        $is_text = true;
        $content = file_get_contents($file_path);
    }

    include 'HTML/file-editor.html';
	
        if ($is_text && $isNormalEditor) {
            echo '<textarea class="mt-2" id="normal-editor" rows="33" cols="120" style="width: 99.5%;">' . htmlspecialchars($content) . '</textarea>';
            echo '<script>document.addEventListener("keydown", function(e) {if ((window.navigator.platform.match("Mac") ? e.metaKey : e.ctrlKey)  && e.keyCode == 83) { e.preventDefault();edit_save(this,"nrl");}}, false);</script>';
        } elseif ($is_text) {
            echo '<div id="editor" contenteditable="true">' . htmlspecialchars($content) . '</div>';
        } else {
            fm_set_msg(lng('FILE EXTENSION HAS NOT SUPPORTED'), 'error');
        }
       
    fm_show_footer();
    exit;
}

// chmod (not for Windows)
if (isset($_GET['chmod']) && !FM_READONLY && !FM_IS_WIN) {
    $file = $_GET['chmod'];
    $file = fm_clean_path($file);
    $file = str_replace('/', '', $file);
    if ($file == '' || (!is_file($path . '/' . $file) && !is_dir($path . '/' . $file))) {
        fm_set_msg(lng('File not found'), 'error');
        $FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL . '?p=' . urlencode($FM_PATH));
    }

    fm_show_header(); // HEADER
    fm_show_nav_path(FM_PATH); // current path

    $file_url = FM_ROOT_URL . (FM_PATH != '' ? '/' . FM_PATH : '') . '/' . $file;
    $file_path = $path . '/' . $file;

    $mode = fileperms($path . '/' . $file);
	
    include 'HTML/chmod.html';
	
    fm_show_footer();
    exit;
}


?>