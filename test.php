<?
require_once(dirname(__FILE__)."/setupcfg.php");

$params=array("srv"=>"192.168.0.1","port"=>995,'md5pass'=>strtoupper(md5("skyguard")) );
$rootca=array("F:\\cfgtest\\ca.crt");
$subca= array("f:\\cfgtest\\corpcert.crt");
$files=array("d:\\111.pcl"=>"{UCSCSDK}\\test.chw");
$PkgSetup= new CPkgSetup("f:\\test.exe",$params,$rootca,$subca,$files);

$PkgSetup->PackIt();

?>