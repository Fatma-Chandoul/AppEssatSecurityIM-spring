<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%@ taglib prefix="form"   uri="http://www.springframework.org/tags/form"%>

<%@ taglib prefix="c"      uri="http://java.sun.com/jsp/jstl/core" %>
    
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<c:set var="cxt" value="${pageContext.request.contextPath }"/>

<title>Insert title here</title>
</head>
<body>
<h1>Ajouter un produit</h1>
<form:form method="POST" action="${cxt}/save" modelAttribute="p">
<p>Titre: <form:input path="titre"/> </p>
<input type="submit" value="Ajouter">

</form:form>
</body>
</html>