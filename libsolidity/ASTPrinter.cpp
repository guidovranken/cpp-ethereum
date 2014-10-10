#include <libsolidity/ASTPrinter.h>
#include <libsolidity/AST.h>

namespace dev {
namespace solidity {

ASTPrinter::ASTPrinter(ptr<ASTNode> _ast, const std::string& _source)
	: m_indentation(0), m_source(_source), m_ast(_ast)
{
}

void ASTPrinter::print(std::ostream& _stream)
{
	m_ostream = &_stream;
	m_ast->accept(*this);
	m_ostream = nullptr;
}


bool ASTPrinter::visit(ContractDefinition& _node)
{
	writeLine("ContractDefinition \"" + _node.getName() + "\"");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(StructDefinition& _node)
{
	writeLine("StructDefinition \"" + _node.getName() + "\"");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(ParameterList& _node)
{
	writeLine("ParameterList");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(FunctionDefinition& _node)
{
	writeLine("FunctionDefinition \"" + _node.getName() + "\"" +
			  (_node.isPublic() ? " - public" : "") +
			  (_node.isDeclaredConst() ? " - const" : ""));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(VariableDeclaration& _node)
{
	writeLine("VariableDeclaration \"" + _node.getName() + "\"");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(TypeName& _node)
{
	writeLine("TypeName");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(ElementaryTypeName& _node)
{
	writeLine(std::string("ElementaryTypeName ") + Token::String(_node.getType()));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(UserDefinedTypeName& _node)
{
	writeLine("UserDefinedTypeName \"" + _node.getName() + "\"");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Mapping& _node)
{
	writeLine("Mapping");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Statement& _node)
{
	writeLine("Statement");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Block& _node)
{
	writeLine("Block");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(IfStatement& _node)
{
	writeLine("IfStatement");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(BreakableStatement& _node)
{
	writeLine("BreakableStatement");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(WhileStatement& _node)
{
	writeLine("WhileStatement");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Continue& _node)
{
	writeLine("Continue");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Break& _node)
{
	writeLine("Break");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Return& _node)
{
	writeLine("Return");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(VariableDefinition& _node)
{
	writeLine("VariableDefinition");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Expression& _node)
{
	writeLine("Expression");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Assignment& _node)
{
	writeLine(std::string("Assignment using operator ") + Token::String(_node.getAssignmentOperator()));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(UnaryOperation& _node)
{
	writeLine(std::string("UnaryOperation (") + (_node.isPrefixOperation() ? "prefix" : "postfix") +
			  ") " + Token::String(_node.getOperator()));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(BinaryOperation& _node)
{
	writeLine(std::string("BinaryOperation using operator ") + Token::String(_node.getOperator()));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(FunctionCall& _node)
{
	writeLine("FunctionCall");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(MemberAccess& _node)
{
	writeLine("MemberAccess to member " + _node.getMemberName());
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(IndexAccess& _node)
{
	writeLine("IndexAccess");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(PrimaryExpression& _node)
{
	writeLine("PrimaryExpression");
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(ElementaryTypeNameExpression& _node)
{
	writeLine(std::string("ElementaryTypeNameExpression ") + Token::String(_node.getType()));
	printSourcePart(_node);
	return goDeeper();
}

bool ASTPrinter::visit(Literal& _node)
{
	const char* tokenString = Token::String(_node.getToken());
	if (tokenString == nullptr)
		tokenString = "----";
	writeLine(std::string("Literal, token: ") + tokenString + " value: " + _node.getValue());
	printSourcePart(_node);
	return goDeeper();
}

void ASTPrinter::endVisit(ASTNode&)
{
	m_indentation--;
}

// @todo instead of this, we could make the default implementation of endVisit call the
// superclass' endVisit
void ASTPrinter::endVisit(ContractDefinition&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(StructDefinition&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(ParameterList&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(FunctionDefinition&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(VariableDeclaration&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(TypeName&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(ElementaryTypeName&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(UserDefinedTypeName&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Mapping&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Statement&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Block&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(IfStatement&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(BreakableStatement&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(WhileStatement&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Continue&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Break&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Return&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(VariableDefinition&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Expression&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Assignment&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(UnaryOperation&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(BinaryOperation&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(FunctionCall&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(MemberAccess&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(IndexAccess&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(PrimaryExpression&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(ElementaryTypeNameExpression&)
{
	m_indentation--;
}

void ASTPrinter::endVisit(Literal&)
{
	m_indentation--;
}

void ASTPrinter::printSourcePart(ASTNode const& _node)
{
	if (!m_source.empty()) {
		Location const& location(_node.getLocation());
		*m_ostream << getIndentation() << "   Source: |"
				   << m_source.substr(location.start, location.end - location.start) << "|\n";
	}
}

std::string ASTPrinter::getIndentation() const
{
	return std::string(m_indentation * 2, ' ');
}

void ASTPrinter::writeLine(const std::string& _line)
{
	*m_ostream << getIndentation() << _line << '\n';
}

} }
