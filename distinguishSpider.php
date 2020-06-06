<?php

    ini_set('max_execution_time', 0);

    ob_end_clean();
    ob_implicit_flush(1);
    if($argc <= 1){
        echo "Missing argument for this script";
        exit;
    }

    $path = $argv[1];
    if(!file_exists($path)){
        echo "File dose not exist";
        exit;
    }



    $ip = read($path);//扫描文件中拥有蜘蛛信息的ip
    $list = analysis($ip['data']);//分析真假蜘蛛
    //真假蜘蛛储存csv文件
    save($path,$list);


    function save($old_path,$data){
        $path_parts = pathinfo($old_path);//获取读取文件名
        $file_name = $path_parts['filename'];
        $csv_name = $file_name.".csv";

        $file = fopen("./".$csv_name, 'w');

        foreach ($data['true'] as $k => $v) {
            fwrite($file, "true,".$v."\r\n");
        }

        foreach ($data['false'] as $k => $v) {
            fwrite($file, "false,".$v."\r\n");
        }

        fclose($file);
        echo "csv save path ".dirname(__FILE__).'/'.$csv_name."\r\n";
    }

    function analysis($ip){
        echo "------ Begin test spider ------\r\n";
        $return = [];

        foreach ($ip as $k=>$v){
            exec("nslookup {$v}",$res);
            $res = implode("",$res);

            if(strpos($res,".baidu.com") || strpos($res,".baidu.jp")){
                echo $v." [true spider]\r\n";
                $return['true'][] = $v;
            }else{
                echo $v." [false spider]\r\n";
                $return['false'][] = $v;
            }

            $res = [];
        }
        echo "------ Begin test spider ------\r\n";
        return $return;
    }

    function read($path){
        echo "------ Begin read log ------\r\n";
        $file = fopen($path, "r");
        $temp = "";
        $temp_arr = [];
        $data = [];
        $return = [];
        $count = 0;
        //输出文本中所有的行，直到文件结束为止。
        while(! feof($file)) {
            $count ++;
            $temp = trim(fgets($file));//fgets()函数从文件指针中读取一行

            echo $count." ".$temp."\r\n";

            //本行日志中包含 Baiduspider 字符串 初步判定为蜘蛛 记录本次访问ip
            if(strpos($temp,"Baiduspider")){
                $temp_arr = explode(' ',$temp);
                $data[] = $temp_arr[1];
            }

        }
        fclose($file);
        echo "------ End read log ------\r\n";
        $return['count'] =  $count;
        $return['origin_num'] = count($data);
        $return['num'] = count(array_unique($data));
        $return['data'] =  array_unique($data);

        return array_unique($return);
    }