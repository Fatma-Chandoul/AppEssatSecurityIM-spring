package tn.essat.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Repository;

import tn.essat.model.Produit;

@Repository
public class GestionImp implements IGestion {
	@Autowired
	@Qualifier("dataSource")
	DataSource dat;

	public List<Produit> getAllProduit() {
		List<Produit> liste = null;
		try {
			liste = new ArrayList<Produit>();
			Connection cnx = dat.getConnection();
			PreparedStatement pr = cnx.prepareStatement("select * from produit");
			ResultSet rs = pr.executeQuery();
			while (rs.next()) {  
				Produit c = new Produit(rs.getInt("id"), rs.getString("titre"));
				liste.add(c);
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		return liste;
	}

	public void addProduit(Produit p) {
		try {
			Connection cnx = dat.getConnection();
			PreparedStatement pr = cnx.prepareStatement("insert into produit values (null,?)");
			pr.setString(1, p.getTitre());
			pr.executeUpdate();

		} catch (Exception e) {

		}
	}

	public void deleteProduit(int id) {
		try {
			Connection cnx = dat.getConnection();

			PreparedStatement pr = cnx.prepareStatement("delete from produit where id=?");
			pr.setInt(1, id);
			pr.executeUpdate();

		} catch (Exception e) {

		}
	}
}
