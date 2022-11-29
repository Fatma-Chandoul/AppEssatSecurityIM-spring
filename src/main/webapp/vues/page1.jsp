<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%@ taglib prefix="form"   uri="http://www.springframework.org/tags/form"%>

<%@ taglib prefix="c"      uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
    
<!DOCTYPE html>
<html>
<head>  
<meta charset="ISO-8859-1">
<c:set var="cxt" value="${pageContext.request.contextPath }"/>

<title>Insert title here</title>
</head>
<body>
<h1>Liste de produits</h1>

<sec:authorize access="isAuthenticated()">Bienvenue Mr/Mlle <sec:authentication property="name"/>
(<a href="<c:url value="/logout" />">Déconnexion</a>) 
</sec:authorize>
<br>
<sec:authorize access="hasRole('ADMIN')">
<a href="${cxt}/ajout">Ajouter un produit</a>

</sec:authorize>

<table border="1">
<tr><th>ID</th><th>Titre</th></tr>
<c:forEach items="${liste }" var="p">
<tr>
<td>${p.id }</td>
<td>${p.titre }</td>
<sec:authorize access="hasRole('ADMIN')">
<td><a href="${cxt}/deleteProduit/${p.id}">Supprimer</a></td>
</sec:authorize>
</tr>
</c:forEach>
</table>

</body>
</html>