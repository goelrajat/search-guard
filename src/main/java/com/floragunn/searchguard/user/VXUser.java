package com.floragunn.searchguard.user;

import java.util.Collection;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class VXUser {
    protected Integer id;
    /**
     * Name
     */
    protected String name;
    /**
     * List of group ids
     */
    protected Collection<Long> groupIdList;
    protected Collection<String> groupNameList;

    /**
     * Default constructor. This will set all the attributes to default value.
     */
    public VXUser ( ) {
    }

    public void setId( Integer id ) {
        this.id = id;
    }

    public Integer getId( ) {
        return this.id;
    }
    
    /**
     * This method sets the value to the member attribute <b>name</b>.
     * You cannot set null to the attribute.
     * @param name Value to set member attribute <b>name</b>
     */
    public void setName( String name ) {
            this.name = name;
    }

    /**
     * Returns the value for the member attribute <b>name</b>
     * @return String - value of member attribute <b>name</b>.
     */
    public String getName( ) {
            return this.name;
    }

    /**
     * This method sets the value to the member attribute <b>groupIdList</b>.
     * You cannot set null to the attribute.
     * @param groupIdList Value to set member attribute <b>groupIdList</b>
     */
    public void setGroupIdList( Collection<Long> groupIdList ) {
            this.groupIdList = groupIdList;
    }

    /**
     * Returns the value for the member attribute <b>groupIdList</b>
     * @return Collection<Long> - value of member attribute <b>groupIdList</b>.
     */
    public Collection<Long> getGroupIdList( ) {
            return this.groupIdList;
    }

    public Collection<String> getGroupNameList() {
            return groupNameList;
    }

    public void setGroupNameList(Collection<String> groupNameList) {
            this.groupNameList = groupNameList;
    }

    /**
     * This return the bean content in string format
     * @return formatedStr
    */
    public String toString( ) {
            String str = "VXUser={";
            str += super.toString();
            str += "name={" + name + "} ";
            str += "id={" + id + "} ";
            str += "groupIdList={" + groupIdList + "} ";
            str += "groupNameList={" + groupNameList + "} ";
            str += "}";
            return str;
    }

}
