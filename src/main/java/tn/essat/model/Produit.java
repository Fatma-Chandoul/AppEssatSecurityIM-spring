package tn.essat.model;

public class Produit {
private int id;
private String titre;
public Produit(int id, String titre) {
	super();
	this.id = id;
	this.titre = titre;
}
public Produit() {
	super();
	// TODO Auto-generated constructor stub
}
public int getId() {
	return id;
}
public void setId(int id) {
	this.id = id;
}
public String getTitre() {
	return titre;
}
public void setTitre(String titre) {
	this.titre = titre;
}

}
